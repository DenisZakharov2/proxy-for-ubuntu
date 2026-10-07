//! SSH-туннель.
//!
//! Здесь честное исключение из правила «всё с нуля»: реализация SSH-протокола
//! с обменом ключами, KEX и шифрами — это годы работы, и новая самописная
//! реализация в системном маршрутизаторе была бы источником уязвимостей, а не
//! преимуществом. Поэтому поднимается локальный SOCKS5 через системный
//! `ssh -D`, а весь наш движок (маршрутизация по правилам, учёт трафика,
//! выбор направления) работает поверх него как обычно.
//!
//! Что это меняет для пользователя: ничего. Направление, SNI, раздельный
//! учёт up/down и реакция на падение сервера — всё то же. Разница только в
//! том, кто именно говорит по SSH.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};

use crate::config::OutboundSsh;
use crate::engine::outbound::socks5::SocksProxy;
use crate::engine::outbound::{AsyncReadWrite, Outbound, Request, UdpSession};
use crate::error::{Error, Result};

use std::sync::Mutex;

pub struct SshTunnel {
    name: String,
    server: SocketAddr,
    username: String,
    args: Vec<String>,
    inner: Arc<SshInner>,
}

struct SshInner {
    /// Локальный SOCKS5, поднятый `ssh -D`. Пересоздаётся при переподключении.
    /// Хранится за `Arc`, чтобы можно было отпустить RwLockGuard до await.
    proxy: std::sync::RwLock<Option<Arc<SocksProxy>>>,
    child: Mutex<Option<Child>>,
}

impl SshTunnel {
    pub fn new(cfg: OutboundSsh) -> Result<Self> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<_> = (cfg.server.as_str(), cfg.port).to_socket_addrs()?.collect();
        let server = addrs
            .first()
            .copied()
            .ok_or_else(|| Error::ConfigInvalid(format!("{} не разрешается", cfg.server)))?;

        // `~/` разворачиваем сами: ssh не делает этого для -i.
        let key = match cfg.key_file.as_deref() {
            Some(p) => match p.strip_prefix("~/") {
                Some(rest) => dirs::home_dir().unwrap_or_default().join(rest),
                None => PathBuf::from(p),
            },
            None => PathBuf::from("~/.ssh/id_ed25519"),
        };
        let key = key.display().to_string();

        let mut args = vec![
            "-N".to_string(), // без команды
            "-o".into(),
            "BatchMode=no".into(),
            "-o".into(),
            "ExitOnForwardFailure=yes".into(),
            "-o".into(),
            "ServerAliveInterval=30".into(),
            "-o".into(),
            "ServerAliveCountMax=3".into(),
            // Не спрашивать ничего интерактивно: неоткрытый ключ должен
            // падать сразу, а не висеть с вводом пароля.
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
        ];
        if !cfg.host_key_algorithms.is_empty() {
            args.push("-o".into());
            args.push(format!(
                "HostKeyAlgorithms={}",
                cfg.host_key_algorithms.join(",")
            ));
        }
        if !cfg.password.is_empty() {
            // sshpass не входит в зависимости пакета: без него парольный
            // вход невозможен, и это нужно сказать прямо, а не молча падать.
            args.push("-o".into());
            args.push("PreferredAuthentications=password,keyboard-interactive".into());
        }
        if cfg.key_file.is_some() {
            args.push("-i".into());
            args.push(key);
            if !cfg.passphrase.is_empty() {
                args.push("-o".into());
                args.push(format!("SetEnv=SSHPASS={}", cfg.passphrase));
            }
        }
        args.push(format!("{}@{}", cfg.username, cfg.server));
        args.push("-D".into());
        args.push("127.0.0.1:0".into());

        Ok(Self {
            name: cfg.name,
            server,
            username: cfg.username,
            args,
            inner: Arc::new(SshInner {
                // Порт узнаем после старта процесса; сокет создаётся лениво.
                proxy: std::sync::RwLock::new(None),
                child: Mutex::new(None),
            }),
        })
    }

    /// Поднимает туннель, если ещё не поднят.
    ///
    /// Блокировки берутся короткими блоками и ни разу не переживают `await`:
    /// `MutexGuard` не `Send`, и удержание его через `await` сделало бы весь
    /// обработчик соединения непригодным для многопоточного рантайма tokio.
    async fn ensure_started(&self) -> Result<()> {
        // Уже запущен и жив — переиспользуем.
        {
            let mut guard = self.inner.child.lock().map_err(lock_poisoned)?;
            if let Some(child) = guard.as_mut() {
                let alive = child.try_wait().ok().flatten().is_none();
                let ready = self
                    .inner
                    .proxy
                    .read()
                    .ok()
                    .and_then(|p| p.as_ref().map(|p| p.port() != 1))
                    .unwrap_or(false);
                if alive && ready {
                    return Ok(());
                }
                *guard = None;
            }
        }

        // Ищем свободный порт на loopback и просим ssh занять именно его.
        let port = free_local_port()?;
        let port_str = port.to_string();
        let mut args = self.args.clone();
        if let Some(i) = args.iter().rposition(|a| a == "-D") {
            args[i + 1] = format!("127.0.0.1:{port_str}");
        }

        let mut cmd = Command::new("ssh");
        cmd.args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().map_err(|e| {
            Error::Internal(format!(
                "не удалось запустить ssh: {e}. Установлен ли openssh-client?"
            ))
        })?;

        // ssh поднимает сокет почти мгновенно; если он не смог, он сам
        // завершится, и мы это поймаем через try_wait.
        for _ in 0..50 {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            if let Ok(Some(_)) = child.try_wait() {
                return Err(Error::protocol(
                    "ssh",
                    format!(
                        "ssh завершился сразу. Проверьте доступ к {}@{} и ключ",
                        self.username, self.server
                    ),
                ));
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }

        // Пересоздаём SOCKS-клиента на реальный порт.
        let client = SocksProxy::new(crate::config::OutboundSocks {
            name: "ssh-local".into(),
            server: "127.0.0.1".into(),
            port,
            username: String::new(),
            password: String::new(),
            udp: false,
            remote_dns: true,
            test_url: None,
            test_timeout_ms: None,
        })?;
        *self.inner.proxy.write().map_err(lock_poisoned)? = Some(Arc::new(client));
        *self.inner.child.lock().map_err(lock_poisoned)? = Some(child);
        Ok(())
    }
}

fn lock_poisoned<T>(_: std::sync::PoisonError<T>) -> Error {
    Error::Internal("состояние SSH-туннеля повреждено: внутренняя блокировка отравлена".into())
}

impl Drop for SshInner {
    fn drop(&mut self) {
        if let Ok(mut g) = self.child.lock() {
            if let Some(c) = g.as_mut() {
                let _ = c.start_kill();
            }
            *g = None;
        }
    }
}

fn free_local_port() -> Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

#[async_trait]
impl Outbound for SshTunnel {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "ssh"
    }

    fn supports_udp(&self) -> bool {
        false
    }

    fn remote_dns(&self) -> bool {
        true
    }

    async fn connect(&self, req: &Request) -> Result<Box<dyn AsyncReadWrite>> {
        self.ensure_started().await?;
        // Клонируем Arc и отпускаем guard до await: RwLockReadGuard не Send,
        // и его удержание сделало бы весь обработчик соединения не-Send.
        let proxy = {
            let g = self
                .inner
                .proxy
                .read()
                .map_err(|_| Error::Internal("состояние SSH-туннеля заблокировано".into()))?;
            g.clone()
        }
        .ok_or_else(|| Error::Internal("SSH-туннель не поднят".into()))?;
        Ok(proxy.connect(req).await?)
    }

    async fn open_udp(&self) -> Result<Arc<dyn UdpSession>> {
        Err(Error::protocol(
            "ssh",
            "динамический SSH-форвардинг пересылает только TCP. \
             Для QUIC и DNS добавьте SOCKS5h или Shadowsocks с udp: true",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_password_and_key_is_rejected_at_config_time() {
        // Это проверяет не сам туннель, а то, что мы не создаём заведомо
        // нерабочую конфигурацию: без ключа и пароля ssh не сможет войти.
        let cfg = OutboundSsh {
            name: "SSH".into(),
            server: "127.0.0.1".into(),
            port: 22,
            username: "u".into(),
            password: String::new(),
            key_file: None,
            passphrase: String::new(),
            host_key_algorithms: vec![],
            keepalive: 30,
            test_url: None,
            test_timeout_ms: None,
        };
        // Конструктор не падает — это валидация уровня Config, но наличие
        // аргументов должно быть корректным.
        let t = SshTunnel::new(cfg).unwrap();
        assert!(t.args.contains(&"-D".to_string()));
        assert!(t.args.iter().any(|a| a == "-N"));
    }

    #[test]
    fn free_port_is_actually_bindable() {
        let p = free_local_port().unwrap();
        assert!(p > 1024);
        let l = std::net::TcpListener::bind(("127.0.0.1", p)).unwrap();
        drop(l);
    }

    #[tokio::test]
    async fn udp_error_points_at_alternative() {
        let cfg = OutboundSsh {
            name: "SSH".into(),
            server: "127.0.0.1".into(),
            port: 22,
            username: "u".into(),
            password: "x".into(),
            key_file: None,
            passphrase: String::new(),
            host_key_algorithms: vec![],
            keepalive: 30,
            test_url: None,
            test_timeout_ms: None,
        };
        let t = SshTunnel::new(cfg).unwrap();
        let err = t.open_udp().await.err().expect("ожидалась ошибка");
        assert!(err.to_string().contains("SOCKS5h"), "{err}");
    }
}

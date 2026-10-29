//! TUN-устройство `pfu0` и userspace-стек.
//!
//! Зачем TUN: REDIRECT умеет перехватывать только TCP (и UDP форвардинга
//! через TPROXY), а локальный UDP — DNS, QUIC, игры — при этом теряет
//! настоящего получателя. TUN забирает пакеты целиком, поэтому получатель
//! известен из заголовка, и в одну схему попадают и TCP, и UDP.
//!
//! Схема:
//! 1. Демон создаёт `pfu0` (`IFF_TUN | IFF_NO_PI`), вешает адрес и маршрут
//!    по умолчанию в таблицу [`crate::engine::nft::TUN_ROUTE_TABLE`].
//! 2. nftables в хуке `output` ставит метку [`crate::engine::nft::FW_MARK_TUN`]
//!    на перехватываемые пакеты, `ip rule` отправляет их в эту таблицу.
//! 3. Ядро пишет пакеты в `pfu0`; демон читает их, разбирает IPv4 + TCP/UDP,
//!    открывает соединение через обычный движок правил и возвращает ответные
//!    пакеты в `pfu0` — ядро доставляет их приложению.
//!
//! Ограничения первой версии: только IPv4, без пересборки фрагментов,
//! без масштабирования окна TCP и без SACK. Подробности — в `packet.rs`,
//! `udp.rs`, `tcp.rs` и `HANDOFF.md`.

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::{Mutex, RwLock};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::config::TunConfig;
use crate::engine::nft::{FW_MARK_TUN, TUN_ROUTE_TABLE};
use crate::engine::router::Engine;
use crate::error::{Error, Result};

pub mod packet;
mod tcp;
mod udp;

/// Ключ потока: (адрес и порт отправителя, адрес и порт получателя).
/// Для TUN отправитель — локальное приложение, получатель — настоящий адрес.
pub type FlowKey = (Ipv4Addr, u16, Ipv4Addr, u16);

/// Запущенное TUN-устройство вместе с читающей задачей.
pub struct Tun {
    device: String,
    /// Конфиг, с которым создано устройство. По нему `reload` решает,
    /// можно ли оставить TUN живым или его надо пересоздать.
    cfg: TunConfig,
    /// Активный движок. `reload` подменяет его, не трогая устройство и уже
    /// открытые соединения: каждое держит свой снимок движка.
    engine: Arc<RwLock<Arc<Engine>>>,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl Tun {
    /// Создаёт устройство, настраивает адрес и маршрут и запускает разбор
    /// пакетов. Ошибка на любом шаге закрывает дескриптор — устройство не
    /// остаётся полунастроенным.
    pub async fn start(engine: Arc<Engine>) -> Result<Self> {
        let cfg = engine.config.tun.clone();
        let io = Arc::new(TunIo::open(&cfg.device).map_err(|e| {
            Error::Internal(format!(
                "не удалось создать TUN {}: {e}. Проверьте, что модуль tun загружен \
                 (sudo modprobe tun) и у демона есть права root",
                cfg.device
            ))
        })?);
        if let Err(e) = configure(&cfg.device, cfg.mtu, &cfg.address).await {
            // Закрываем дескриптор: ядро удалит устройство и маршрут.
            drop(io);
            return Err(e);
        }
        let cancel = CancellationToken::new();
        let shared = Arc::new(RwLock::new(engine));
        let task = tokio::spawn(run(shared.clone(), io, cancel.clone()));
        tracing::info!(
            device = %cfg.device,
            mtu = cfg.mtu,
            address = %cfg.address,
            table = TUN_ROUTE_TABLE,
            mark = format_args!("{FW_MARK_TUN:#x}"),
            "TUN запущен"
        );
        Ok(Self {
            device: cfg.device.clone(),
            cfg,
            engine: shared,
            cancel,
            task: Some(task),
        })
    }

    /// Конфиг, с которым создано устройство: по нему решается, можно ли
    /// переиспользовать TUN после `reload`.
    pub fn config(&self) -> &TunConfig {
        &self.cfg
    }

    /// Подменяет движок для новых пакетов. Открытые соединения продолжают
    /// жить со своим снимком: их правило и счётчики не должны меняться
    /// задним числом.
    pub async fn swap_engine(&self, engine: Arc<Engine>) {
        *self.engine.write().await = engine;
    }

    /// Останавливает разбор пакетов и дожидается закрытия дескриптора:
    /// без этого повторный `connect` не сможет создать устройство с тем же
    /// именем (ядро ответит EBUSY).
    pub async fn stop(&mut self) {
        tracing::info!(device = %self.device, "TUN останавливается");
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    pub fn device(&self) -> &str {
        &self.device
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Дескриптор TUN с асинхронным чтением и записью пакетов.
pub(crate) struct TunIo {
    fd: AsyncFd<OwnedFd>,
}

impl TunIo {
    fn open(name: &str) -> io::Result<Self> {
        let fd = open_device(name)?;
        Ok(Self {
            fd: AsyncFd::new(fd)?,
        })
    }

    /// Читает один пакет. TUN отдаёт ровно один пакет на `read`.
    pub(crate) async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = self.fd.readable().await?;
            let result = ready.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match result {
                Ok(r) => return r,
                // Готовность оказалась ложной — ждём следующую.
                Err(_) => continue,
            }
        }
    }

    /// Пишет один пакет. Частичная запись для TUN невозможна: либо пакет
    /// принят целиком, либо ошибка.
    pub(crate) async fn write(&self, packet: &[u8]) -> io::Result<()> {
        loop {
            let mut ready = self.fd.writable().await?;
            let result = ready.try_io(|inner| {
                let n = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        packet.as_ptr() as *const libc::c_void,
                        packet.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else if n as usize != packet.len() {
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TUN принял не весь пакет",
                    ))
                } else {
                    Ok(())
                }
            });
            match result {
                Ok(r) => return r,
                Err(_) => continue,
            }
        }
    }
}

fn open_device(name: &str) -> io::Result<OwnedFd> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "недопустимое имя TUN {name:?}: нужно 1..{} символов",
                libc::IFNAMSIZ - 1
            ),
        ));
    }
    let c_name = std::ffi::CString::new("/dev/net/tun")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "пустой путь к TUN"))?;
    let fd = unsafe {
        libc::open(
            c_name.as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.as_bytes().iter().enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut ifr) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Адрес, MTU и маршрут по умолчанию в таблице TUN.
async fn configure(device: &str, mtu: u16, address: &str) -> Result<()> {
    run_cmd(&format!("ip link set dev {device} up mtu {mtu}")).await?;
    run_cmd(&format!("ip addr replace {address} dev {device}")).await?;
    run_cmd(&format!(
        "ip route replace default dev {device} table {TUN_ROUTE_TABLE}"
    ))
    .await?;
    // Пакеты из userspace приходят в устройство с чужим адресом источника:
    // строгий rp_filter отбросил бы их как «пришедшие не с той стороны».
    // Для TUN-интерфейса проверка бессмысленна — выключаем её точечно.
    let rp = format!("/proc/sys/net/ipv4/conf/{device}/rp_filter");
    if let Err(e) = std::fs::write(&rp, "0") {
        tracing::warn!(path = %rp, error = %e, "не удалось выключить rp_filter на TUN");
    }
    Ok(())
}

async fn run_cmd(cmd: &str) -> Result<()> {
    let out = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .await
        .map_err(|e| Error::Internal(format!("не удалось выполнить {cmd:?}: {e}")))?;
    if !out.status.success() {
        return Err(Error::Apply(format!(
            "{cmd}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Читает пакеты из TUN и раздаёт их обработчикам TCP/UDP. Потоки
/// (соединения) живут в `JoinSet` этой задачи, поэтому остановка TUN
/// гарантированно дожидается их завершения и закрытия дескриптора.
async fn run(engine: Arc<RwLock<Arc<Engine>>>, io: Arc<TunIo>, cancel: CancellationToken) {
    let mut joins: JoinSet<()> = JoinSet::new();
    let udp = udp::UdpFlows::new();
    let tcp = tcp::TcpFlows::new();
    let mut buf = vec![0u8; 65_536];

    loop {
        let n = tokio::select! {
            _ = cancel.cancelled() => break,
            Some(done) = joins.join_next(), if !joins.is_empty() => {
                if let Err(e) = done {
                    tracing::debug!(error = %e, "поток TUN завершился с ошибкой");
                }
                continue;
            }
            result = io.read(&mut buf) => match result {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(error = %e, "TUN: чтение пакета не удалось — стек остановлен");
                    break;
                }
            },
        };
        if n == 0 {
            continue;
        }
        let Some(packet) = packet::parse_ipv4(&buf[..n]) else {
            continue;
        };
        // Снимок движка на пакет: `reload` мог только что его подменить.
        // Held-лок не переживает await — клонируем и отпускаем.
        let engine = engine.read().await.clone();
        match packet.protocol {
            packet::PROTO_UDP => {
                udp.dispatch(packet, &io, &engine, &cancel, &mut joins)
                    .await
            }
            packet::PROTO_TCP => {
                tcp.dispatch(packet, &io, &engine, &cancel, &mut joins)
                    .await
            }
            // ICMP и прочее не проксируем: приложение получит отказ и уйдёт
            // на TCP/UDP, а молча съеденный ICMP хуже явного пропуска.
            _ => {}
        }
    }

    // Штатное завершение: потоки слушают `cancel` и успевают записать
    // статистику в breakdown. Ждать вечно нельзя — запись в зависший upstream
    // не должна задерживать выключение, поэтому через 2 с обрываем.
    let drain = async { while joins.join_next().await.is_some() {} };
    if tokio::time::timeout(std::time::Duration::from_secs(2), drain)
        .await
        .is_err()
    {
        tracing::debug!("часть потоков TUN не закрылась за 2 с — обрываем");
        joins.shutdown().await;
    }
}

/// Общий реестр UDP-потоков, чтобы завершающаяся задача убирала себя сама.
pub(crate) type UdpRegistry = Arc<Mutex<HashMap<FlowKey, tokio::sync::mpsc::Sender<Vec<u8>>>>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_device_names_are_rejected_before_ioctl() {
        assert!(open_device("").is_err());
        assert!(open_device("x".repeat(libc::IFNAMSIZ).as_str()).is_err());
    }

    #[test]
    fn flow_key_is_address_and_port_pairs() {
        let key: FlowKey = (
            Ipv4Addr::new(10, 0, 0, 1),
            1234,
            Ipv4Addr::new(93, 184, 216, 34),
            443,
        );
        assert_eq!(key.1, 1234);
        assert_eq!(key.3, 443);
    }
}

//! Демон proxy-for-ubuntu.
//!
//! Запускается systemd от root, слушает управляющий сокет и держит
//! системные правила. GUI общается с ним по IPC, а `pfu-cli` — для
//! headless-конфигурации.

use std::process::ExitCode;

use pfu::engine::dns;
use pfu::engine::geo::GeoRegistry;
use pfu::engine::nft;
use pfu::error::Result;
use pfu::ipc::Server;
use pfu::paths;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("--daemon");

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("не удалось создать runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let outcome = rt.block_on(async move {
        match mode {
            "--daemon" | "-d" => run_daemon().await,
            "--check" => run_check().await,
            "--version" | "-V" => {
                println!(
                    "proxy-for-ubuntud {} (api {})",
                    pfu::VERSION,
                    pfu::API_VERSION
                );
                Ok(())
            }
            "--help" | "-h" => {
                print_help();
                Ok(())
            }
            other => {
                eprintln!("неизвестный аргумент: {other}");
                print_help();
                Err(pfu::Error::ConfigInvalid(format!(
                    "неизвестный аргумент {other}"
                )))
            }
        }
    });

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            if let Some(h) = e.hint() {
                eprintln!("подсказка: {h}");
            }
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    eprintln!(
        "proxy-for-ubuntud {}\n\
         \n\
         Демон системной маршрутизации proxy-for-ubuntu.\n\
         Обычно запускается через systemd, вручную запускать не нужно.\n\
         \n\
         Использование:\n  \
           proxy-for-ubuntud --daemon    запустить демон (по умолчанию)\n  \
           proxy-for-ubuntud --check     проверить окружение и выйти\n  \
           proxy-for-ubuntud --version   показать версию",
        pfu::VERSION
    );
}

fn init_logging() -> Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    // Уровень и файл читаем из конфига, но ошибка чтения не должна мешать
    // старту: демон обязан подняться даже с неисправным config.yaml.
    let cfg = pfu::config::Config::load(
        &paths::config_path(),
        &pfu::config::read_env_file(&paths::env_file()),
    )
    .ok();
    let level = cfg
        .as_ref()
        .map(|c| c.log.level.clone())
        .unwrap_or_else(|| "info".into());
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("pfu={0},proxy_for_ubuntu={0}", level)));

    // Слои разных типов (файл и stderr) складываем как trait-объекты.
    let mut layers: Vec<
        Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>,
    > = Vec::new();
    if let Some(file) = cfg.and_then(|c| c.log.file) {
        // rolling::never принимает каталог и префикс, а не готовый путь.
        let path = std::path::PathBuf::from(&file);
        let dir = path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let prefix = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "engine".into());
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("не удалось создать каталог для лога {}: {e}", dir.display());
        } else {
            let appender = tracing_appender::rolling::never(&dir, prefix);
            layers.push(Box::new(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(appender),
            ));
        }
    }
    // stderr перехватывает systemd и уходит в journald.
    layers.push(Box::new(
        tracing_subscriber::fmt::layer().with_writer(std::io::stderr),
    ));

    tracing_subscriber::registry()
        .with(layers)
        .with(filter)
        .init();
    Ok(())
}

async fn run_daemon() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "proxy-for-ubuntud должен запускаться от root.\n\
             Он управляет TUN, nftables и маршрутами — обычному пользователю это недоступно.\n\
             Запустите: sudo systemctl start proxy-for-ubuntud"
        );
        return Err(pfu::Error::Permission(
            "демон должен работать от root".into(),
        ));
    }

    init_logging()?;
    prepare_dirs()?;
    tracing::info!("proxy-for-ubuntud {} стартует", pfu::VERSION);

    // Перехват, оставшийся от предыдущего аварийного завершения, снимаем на
    // старте: иначе машина осталась бы без сети до переустановки пакета.
    nft::teardown().await.ok();
    clear_stale_socket();

    // Уже загруженный конфиг нужен, чтобы демон знал профили и geo-наборы.
    let geo = GeoRegistry::load(&[]);
    tracing::info!(geo_sets = geo.list().len(), "geo-наборы загружены");

    let server = std::sync::Arc::new(Server::new());
    let socket = paths::ctl_socket();
    let outcome = server.serve(socket).await;

    match &outcome {
        Ok(()) => tracing::info!("демон остановлен"),
        Err(e) => tracing::error!("демон остановился с ошибкой: {e}"),
    }
    // Снимаем системные правила при любом завершении: оставленные
    // правила nftables уводят машину в никуда после остановки демона.
    nft::teardown().await.ok();
    outcome
}

/// Проверка окружения для `systemctl start` (ExecStartPre) и для `pfu-cli doctor`.
async fn run_check() -> Result<()> {
    let mut problems = 0;

    let (nft_ok, nft_ver) = nft::check_available().await;
    println!(
        "nftables: {} ({nft_ver})",
        if nft_ok { "есть" } else { "НЕТ" }
    );
    if !nft_ok {
        problems += 1;
    }

    let tun = std::path::Path::new("/dev/net/tun").exists();
    println!("/dev/net/tun: {}", if tun { "есть" } else { "НЕТ" });
    if !tun {
        problems += 1;
    }

    let root = unsafe { libc::geteuid() } == 0;
    println!("права: {}", if root { "root" } else { "не root" });

    let config = paths::config_path();
    println!(
        "конфиг: {} ({})",
        config.display(),
        if config.exists() {
            "есть"
        } else {
            "будет создан при первом запуске"
        }
    );

    for (id, name, port) in [
        ("TCP", "перехват TCP", paths::redirect_port()),
        ("UDP", "перехват UDP", paths::tproxy_port()),
    ] {
        let _ = id;
        let free = std::net::TcpListener::bind(("127.0.0.1", port)).is_ok();
        println!(
            "порт {port} ({name}): {}",
            if free {
                "свободен"
            } else {
                "ЗАНЯТ"
            }
        );
    }

    if problems > 0 {
        eprintln!("\nОбнаружены проблемы: {problems}. Запуск будет невозможен.");
        return Err(pfu::Error::Internal(format!(
            "проблем в окружении: {problems}"
        )));
    }
    println!("\nОкружение готово.");
    Ok(())
}

fn prepare_dirs() -> Result<()> {
    paths::ensure_secure_dir(&paths::lib_dir())?;
    paths::ensure_secure_dir(&paths::rollback_dir())?;
    paths::ensure_dir(&paths::geo_dir())?;
    paths::ensure_dir(&paths::geo_dir().join("geoip"))?;
    paths::ensure_dir(&paths::geo_dir().join("geosite"))?;
    // Каталог для сокета: /run очищается при перезагрузке, поэтому группа
    // и права на нём должны выставляться каждый раз при старте.
    if let Some(parent) = paths::ctl_socket().parent() {
        paths::ensure_dir(parent)?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750));
        let _ = std::process::Command::new("chgrp")
            .arg(pfu::DAEMON_USER)
            .arg(parent)
            .status();
    }
    Ok(())
}

fn clear_stale_socket() {
    let p = paths::ctl_socket();
    if p.exists() {
        // Сокет считается устаревшим, если по нему никто не слушает.
        if std::os::unix::net::UnixStream::connect(&p).is_err() {
            tracing::warn!("удаляем потерянный сокет {}", p.display());
            let _ = std::fs::remove_file(&p);
        } else {
            tracing::error!(
                "сокет {} уже занят — вероятно, демон уже запущен",
                p.display()
            );
            std::process::exit(1);
        }
    }
}

/// Периодическая уборка кэшей DNS. Живёт, пока жив демон.
pub fn spawn_gc_task(
    resolver: std::sync::Arc<dyn Fn() + Send + Sync>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            resolver();
        }
    })
}

/// Только для тестов и диагностики: собираем резолвер один раз.
pub fn build_resolver(cfg: pfu::config::Config) -> Result<std::sync::Arc<dns::Resolver>> {
    dns::Resolver::new(cfg.dns)
}

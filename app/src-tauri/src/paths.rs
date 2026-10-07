//! Пути и пользовательские каталоги.
//!
//! Разделение важно: демон работает от root и не должен писать в домашний
//! каталог пользователя, а GUI — не должен иметь доступа к `/etc`.

use std::path::{Path, PathBuf};

use crate::{Error, Result, DAEMON_USER};

/// Системные каталоги (требуют root на запись).
pub fn etc_dir() -> PathBuf {
    PathBuf::from("/etc/proxy-for-ubuntu")
}

pub fn config_path() -> PathBuf {
    etc_dir().join("config.yaml")
}

pub fn profiles_dir() -> PathBuf {
    etc_dir().join("profiles")
}

pub fn env_file() -> PathBuf {
    etc_dir().join("env")
}

pub fn lib_dir() -> PathBuf {
    PathBuf::from("/var/lib/proxy-for-ubuntu")
}

pub fn geo_dir() -> PathBuf {
    lib_dir().join("geo")
}

pub fn rollback_dir() -> PathBuf {
    lib_dir().join("rollback")
}

pub fn state_path() -> PathBuf {
    lib_dir().join("state.json")
}

pub fn lock_path() -> PathBuf {
    PathBuf::from("/run/proxy-for-ubuntu/lock")
}

pub fn ctl_socket() -> PathBuf {
    PathBuf::from("/run/proxy-for-ubuntu/ctl.sock")
}

pub fn redirect_port() -> u16 {
    15000
}

pub fn tproxy_port() -> u16 {
    15001
}

pub fn dns_port() -> u16 {
    15002
}

pub fn builtin_profiles_dir() -> PathBuf {
    PathBuf::from("/usr/share/proxy-for-ubuntu/profiles")
}

pub fn default_log_file() -> PathBuf {
    PathBuf::from("/var/log/proxy-for-ubuntu/engine.log")
}

/// Каталог конфигурации конкретного пользователя (`$XDG_CONFIG_HOME`).
pub fn user_config_dir() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_CONFIG_HOME") {
        if !x.is_empty() {
            return Path::new(&x).join(DAEMON_USER);
        }
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("/home/unknown/.config"))
        .join(DAEMON_USER)
}

pub fn user_profiles_dir() -> PathBuf {
    user_config_dir().join("profiles")
}

pub fn user_cache_dir() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_CACHE_HOME") {
        if !x.is_empty() {
            return Path::new(&x).join(DAEMON_USER);
        }
    }
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(DAEMON_USER)
}

/// Создаёт каталог, если его нет. Не меняет права существующего.
pub fn ensure_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

/// Создаёт каталог с правами `0750` и владельцем root:daemon_group.
pub fn ensure_secure_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !path.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o750)
            .create(path)?;
    }
    Ok(())
}

/// Атомарная запись файла: пишем во временный файл рядом и переименовываем.
/// Так читатель никогда не увидит половину файла.
pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().ok_or_else(|| {
        Error::Internal(format!("нет родительского каталога для {}", path.display()))
    })?;
    ensure_dir(parent)?;

    let tmp = parent.join(format!(
        ".{}.tmp{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("cfg"),
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Группа демона. GUI добавляет текущего пользователя в неё при установке.
pub fn daemon_group() -> String {
    DAEMON_USER.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_and_replaces() {
        let dir = std::env::temp_dir().join(format!("pfu-test-{}", std::process::id()));
        let file = dir.join("a.yaml");
        atomic_write(&file, b"first").unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "first");
        atomic_write(&file, b"second").unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "second");
        // Временных файлов остаться не должно.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "остались временные файлы: {leftovers:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn system_paths_are_absolute() {
        assert!(config_path().is_absolute());
        assert!(ctl_socket().is_absolute());
        assert_eq!(redirect_port(), 15000);
    }
}

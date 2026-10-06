//! Гео-наборы: текстовые списки CIDR и доменов с локальным кэшем.
//!
//! Свой формат вместо чужих бинарных баз — принципиальное решение: файлы
//! читаются глазами, правятся руками, диффятся в git и не ломаются при смене
//! версии. Каждая строка — запись, `#` начинает комментарий, пустые строки
//! игнорируются.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use ipnet::IpNet;
use serde::Serialize;

pub use crate::config::{GeoKind, GeoSource};
use crate::error::{Error, Result};
use crate::paths;

/// Загруженный набор. Читается из всех правил параллельно, поэтому внутри —
/// один раз построенные неизменяемые структуры под `RwLock`.
pub struct GeoSet {
    kind: GeoKind,
    tag: String,
    entries: Vec<GeoEntry>,
    updated_at: i64,
    source: String,
    sha256: String,
}

/// Один элемент набора. Храним вместе с исходной строкой, чтобы `geo.preview`
/// мог показать пользователю ровно то, что лежит в файле.
#[derive(Debug, Clone)]
pub enum GeoEntry {
    Cidr(IpNet),
    Domain(String),
    /// Заглушка на случай битого файла — не роняет загрузку, попадает в счётчик.
    Invalid { line: String },
}

impl GeoEntry {
    fn parse(kind: GeoKind, line: &str) -> GeoEntry {
        match kind {
            GeoKind::Geoip => line
                .parse::<IpNet>()
                .map(GeoEntry::Cidr)
                // Частая ошибка в чужих списках: `1.2.3.4/32` иногда пишут без маски.
                .or_else(|_| line.parse::<IpAddr>().map(|ip| GeoEntry::Cidr(IpNet::from(ip))))
                .unwrap_or_else(|_| GeoEntry::Invalid { line: line.to_string() }),
            GeoKind::Geosite => GeoEntry::Domain(line.to_ascii_lowercase()),
        }
    }

    /// Точное совпадение адреса по битовой маске.
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        match self {
            GeoEntry::Cidr(net) => net.contains(&ip),
            _ => false,
        }
    }

    /// `domain-suffix`: `a.example.com` попадает под `example.com`.
    pub fn matches_domain(&self, domain: &str) -> bool {
        match self {
            GeoEntry::Domain(d) => {
                domain == d
                    || (domain.len() > d.len()
                        && domain.ends_with(d)
                        && domain.as_bytes()[domain.len() - d.len() - 1] == b'.')
            }
            _ => false,
        }
    }
}

/// Реестр всех наборов. Отдаётся наружу как `&` и не меняется после загрузки.
pub struct GeoRegistry {
    sets: HashMap<(GeoKind, String), Arc<GeoSetHandle>>,
}

impl std::fmt::Debug for GeoRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoRegistry").field("count", &self.sets.len()).finish()
    }
}

/// Обёртка: наружу отдаём `Arc`, внутри RwLock — чтобы можно было догружать
/// наборы без пересборки движка (обновление geo на лету).
pub struct GeoSetHandle {
    inner: RwLock<GeoSet>,
}

impl std::fmt::Debug for GeoSetHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GeoSetHandle")
    }
}

impl GeoSetHandle {
    pub fn entries(&self) -> Vec<GeoEntry> {
        self.inner.read().map(|g| g.entries.clone()).unwrap_or_default()
    }

    pub fn meta(&self) -> GeoMeta {
        self.inner
            .read()
            .map(|g| GeoMeta {
                kind: g.kind,
                tag: g.tag.clone(),
                count: g.entries.len(),
                updated_at: g.updated_at,
                source: g.source.clone(),
                sha256: g.sha256.clone(),
            })
            .unwrap_or(GeoMeta {
                kind: GeoKind::Geoip,
                tag: String::new(),
                count: 0,
                updated_at: 0,
                source: String::new(),
                sha256: String::new(),
            })
    }
}

pub type Arc<T> = std::sync::Arc<T>;

#[derive(Debug, Clone, Serialize)]
pub struct GeoMeta {
    pub kind: GeoKind,
    pub tag: String,
    pub count: usize,
    pub updated_at: i64,
    pub source: String,
    pub sha256: String,
}

impl GeoSet {
    pub fn parse(kind: GeoKind, tag: &str, text: &str, source: &str) -> Self {
        let entries: Vec<GeoEntry> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| GeoEntry::parse(kind, l))
            .collect();
        let invalid = entries.iter().filter(|e| matches!(e, GeoEntry::Invalid { .. })).count();
        if invalid > 0 {
            tracing::warn!(set = tag, kind = ?kind, invalid, "часть строк набора не распознана");
        }
        Self {
            kind,
            tag: tag.to_string(),
            entries,
            updated_at: now(),
            source: source.to_string(),
            sha256: String::new(),
        }
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn set_file(kind: GeoKind, tag: &str) -> PathBuf {
    let sub = match kind {
        GeoKind::Geoip => "geoip",
        GeoKind::Geosite => "geosite",
    };
    paths::geo_dir().join(sub).join(format!("{}.txt", sanitize_tag(tag)))
}

/// Имя тега входит в имя файла — не пропускаем никакие символы, кроме
/// букв, цифр, дефиса и подчёркивания. Иначе `../../etc/passwd` в конфиге
/// увёл бы запись за пределы каталога.
fn sanitize_tag(tag: &str) -> String {
    let cleaned: String = tag
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    if cleaned.is_empty() {
        "unnamed".into()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod sanitize_tag {
    #[test]
    fn neutralizes_path_traversal() {
        use super::sanitize_tag;
        // 6 символов `../../` превращаются в 6 подчёркиваний.
        assert_eq!(sanitize_tag("../../etc/passwd"), "______etc_passwd");
        assert!(!sanitize_tag("..%2fetc%2fpasswd").contains('/'));
        assert_eq!(sanitize_tag("category-ads-all"), "category-ads-all");
        assert_eq!(sanitize_tag(""), "unnamed");
    }
}

impl GeoRegistry {
    /// Пустой реестр — для тестов и для запуска без geo-данных.
    pub fn empty() -> Self {
        Self { sets: HashMap::new() }
    }

    /// Загружает с диска все наборы, упомянутые в правилах, плюс все, что уже
    /// лежат в каталоге. Не падает из-за отсутствующих файлов: отсутствие
    /// набора — не ошибка конфига, а повод для предупреждения.
    pub fn load(needed: &[(GeoKind, String)]) -> Self {
        let mut sets = HashMap::new();
        for kind_dir in [GeoKind::Geoip, GeoKind::Geosite] {
            let dir = paths::geo_dir().join(match kind_dir {
                GeoKind::Geoip => "geoip",
                GeoKind::Geosite => "geosite",
            });
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for entry in rd.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("txt") {
                    continue;
                }
                let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
                let key = (kind_dir, stem.to_string());
                if !needed.is_empty() && !needed.contains(&key) {
                    continue;
                }
                if let Ok(handle) = Self::load_file(&path, kind_dir, stem, &std::fs::metadata(&path).ok().map(|m| m.len() as i64).unwrap_or(0)) {
                    sets.insert(key, Arc::new(handle));
                }
            }
        }
        Self { sets }
    }

    fn load_file(path: &Path, kind: GeoKind, tag: &str, _size: &i64) -> Result<GeoSetHandle> {
        let text = std::fs::read_to_string(path)?;
        let mut set = GeoSet::parse(kind, tag, &text, path.display().to_string().as_str());
        set.sha256 = sha256_hex(text.as_bytes());
        Ok(GeoSetHandle { inner: RwLock::new(set) })
    }

    /// Набор по тегу. `None` — если его скачать не удалось; правило с таким
    /// тегом просто не сработает, а не обрушит движок.
    pub fn get(&self, kind: GeoKind, tag: &str) -> Option<Arc<GeoSetHandle>> {
        self.sets.get(&(kind, tag.to_string())).cloned()
    }

    pub fn list(&self) -> Vec<GeoMeta> {
        let mut v: Vec<GeoMeta> = self.sets.values().map(|h| h.meta()).collect();
        v.sort_by(|a, b| (a.kind as u8, &a.tag).cmp(&(b.kind as u8, &b.tag)));
        v
    }

    /// Скачивает набор и кладёт на диск. Возвращает количество записей.
    pub async fn update(src: &GeoSource) -> Result<usize> {
        let client = crate::engine::http_client()?;
        let resp = client
            .get(&src.url)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("загрузка {}: {e}", src.url)))?;
        if !resp.status().is_success() {
            return Err(Error::Internal(format!(
                "{} вернул HTTP {}",
                src.url,
                resp.status()
            )));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::Internal(format!("чтение ответа: {e}")))?;

        if !src.sha256.is_empty() {
            let got = sha256_hex(&body);
            if !got.eq_ignore_ascii_case(&src.sha256) {
                return Err(Error::Internal(format!(
                    "sha256 не совпал для {}: ожидали {}, получили {}",
                    src.url, src.sha256, got
                )));
            }
        }

        let text = String::from_utf8_lossy(&body);
        let set = GeoSet::parse(src.kind, &src.tag, &text, &src.url);
        let count = set.entries.len();
        let path = set_file(src.kind, &src.tag);
        crate::paths::atomic_write(&path, body.as_ref())?;
        tracing::info!(kind = ?src.kind, tag = %src.tag, count, "geo-набор обновлён");
        Ok(count)
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_geoip_cidr_with_and_without_mask() {
        let s = GeoSet::parse(GeoKind::Geoip, "cn", "1.0.1.0/24\n8.8.8.8\n# c\n\nbad-line", "t");
        assert_eq!(s.entries.len(), 3);
        assert!(s.entries[0].contains_ip("1.0.1.5".parse().unwrap()));
        assert!(s.entries[1].contains_ip("8.8.8.8".parse().unwrap()));
        assert!(!s.entries[1].contains_ip("8.8.4.4".parse().unwrap()));
    }

    #[test]
    fn geoip_respects_mask() {
        let s = GeoSet::parse(GeoKind::Geoip, "t", "10.0.0.0/8", "t");
        assert!(s.entries[0].contains_ip("10.255.255.255".parse().unwrap()));
        assert!(!s.entries[0].contains_ip("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn domain_suffix_matching() {
        let s = GeoSet::parse(GeoKind::Geosite, "t", "example.com", "t");
        let e = &s.entries[0];
        assert!(e.matches_domain("example.com"));
        assert!(e.matches_domain("a.example.com"));
        assert!(e.matches_domain("deep.a.example.com"));
        // Не должно матчить ни суффикс без точки, ни поддомен другого домена.
        assert!(!e.matches_domain("notexample.com"));
        assert!(!e.matches_domain("example.com.evil.net"));
    }

    #[test]
    fn geosite_lowercases() {
        let s = GeoSet::parse(GeoKind::Geosite, "t", "Example.COM", "t");
        assert!(s.entries[0].matches_domain("example.com"));
    }

    #[test]
    fn comments_and_blanks_skipped() {
        let s = GeoSet::parse(GeoKind::Geosite, "t", "# c\n\n  a.com  \n\t# b\nb.com", "t");
        assert_eq!(s.entries.len(), 2);
    }

    #[test]
    fn sha256_is_stable() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

//! Схема конфигурации.
//!
//! Формат — Clash-подобный YAML, описанный в docs/CONFIG.md. Здесь только
//! разбор и валидация: превращение строк в типизированные структуры, проверка
//! ссылочной целостности (все действия правил указывают на существующий
//! outbound или группу) и подстановка `${VAR}` из env-файла.
//!
//! Компиляция правил в исполняемую форму живёт в [`crate::engine::rules`] и
//! вызывается отдельно — здесь держим только «сырое» представление.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

// ──────────────────────────────── корневой конфиг ────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Версия IPC-контракта, для которого конфиг написан.
    #[serde(default = "default_api")]
    pub api: u32,

    #[serde(default)]
    pub log: LogConfig,

    #[serde(default)]
    pub dns: DnsConfig,

    #[serde(default)]
    pub intercept: InterceptConfig,

    #[serde(default)]
    pub tun: TunConfig,

    #[serde(default)]
    pub geo: GeoConfig,

    #[serde(default)]
    pub groups: Vec<GroupConfig>,

    #[serde(default)]
    pub outbounds: Vec<Outbound>,

    #[serde(default)]
    pub rules: Vec<Rule>,

    /// Что делать со всем, что не попало ни под одно правило.
    ///
    /// В Rust `final` — ключевое слово, поэтому поле называется
    /// `final_policy`, а пользователю — в YAML и в JSON — видно как `final`.
    #[serde(rename = "final", default = "default_final")]
    pub final_policy: Policy,

    /// Ограничения скорости и числа соединений.
    #[serde(default)]
    pub limits: LimitsConfig,
}

fn default_api() -> u32 {
    crate::API_VERSION
}
fn default_final() -> Policy {
    Policy::Direct
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api: default_api(),
            log: LogConfig::default(),
            dns: DnsConfig::default(),
            intercept: InterceptConfig::default(),
            tun: TunConfig::default(),
            geo: GeoConfig::default(),
            groups: Vec::new(),
            // Безымянный DIRECT создаётся всегда, даже если пользователь его не
            // указал: правила и группы ссылаются на него по имени.
            outbounds: vec![Outbound::Direct(OutboundDirect {
                name: "DIRECT".into(),
                test_url: None,
                test_timeout_ms: None,
            })],
            rules: Vec::new(),
            final_policy: Policy::Direct,
            limits: LimitsConfig::default(),
        }
    }
}

impl Config {
    /// Разбирает YAML с подстановкой переменных окружения.
    pub fn parse(text: &str, env: &HashMap<String, String>) -> Result<Self> {
        // Подстановка не должна молча превращать отсутствующий секрет в пустую
        // строку: тогда конфиг «валиден», а соединение падает с невнятной
        // ошибкой аутентификации. Список имён — без значений.
        let missing = missing_env_refs(text, env);
        if !missing.is_empty() {
            return Err(Error::ConfigInvalid(format!(
                "в конфиге есть переменные без значения: {} — добавьте их в /etc/proxy-for-ubuntu/env или задайте значение по умолчанию ${{VAR:-...}}",
                missing.join(", ")
            )));
        }
        let expanded = expand_env(text, env);
        let cfg: Config =
            serde_yaml::from_str(&expanded).map_err(|e| Error::ConfigInvalid(format!("{e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path, env: &HashMap<String, String>) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Error::ConfigInvalid(format!("не удалось прочитать {}: {e}", path.display()))
        })?;
        Self::parse(&text, env)
    }

    /// Чтение существующего конфига для показа пользователю. Отличается от
    /// [`Config::load`] мягкой валидацией — см. [`Config::validate_for_read`].
    pub fn load_for_read(path: &Path, env: &HashMap<String, String>) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Error::ConfigInvalid(format!("не удалось прочитать {}: {e}", path.display()))
        })?;
        let expanded = expand_env(&text, env);
        let cfg: Config =
            serde_yaml::from_str(&expanded).map_err(|e| Error::ConfigInvalid(format!("{e}")))?;
        cfg.validate_for_read()?;
        Ok(cfg)
    }

    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(self).map_err(Error::from)
    }

    /// Проверка ссылочной целостности. Не делает сетевых запросов.
    ///
    /// Строгий вариант: используется перед применением. Конфиг без единого
    /// прокси (состояние сразу после установки) здесь считается ошибкой —
    /// применять такое бессмысленно.
    pub fn validate(&self) -> Result<()> {
        self.validate_inner(true)
    }

    /// Мягкий вариант: для чтения (`config.get`, `pfu-cli rules`, список
    /// профилей). На чистой установке прокси ещё нет, и из-за этого
    /// показать пользователю его собственную конфигурацию нельзя.
    pub fn validate_for_read(&self) -> Result<()> {
        self.validate_inner(false)
    }

    /// Перехват вообще что-то делает: включён хотя бы один путь (TCP, UDP или
    /// TUN). Если всё выключено, правила не создаются целиком, и `connect`
    /// ничего не трогает в системе.
    pub fn interception_active(&self) -> bool {
        self.intercept.tcp != TcpMode::Off || self.intercept.udp != UdpMode::Off || self.tun.enabled
    }

    fn validate_inner(&self, strict: bool) -> Result<()> {
        if self.api > crate::API_VERSION {
            return Err(Error::ConfigInvalid(format!(
                "конфиг написан для api: {}, а эта версия понимает только {} — обновите пакет",
                self.api,
                crate::API_VERSION
            )));
        }

        if self.intercept.tcp == TcpMode::Off && self.intercept.udp == UdpMode::Off {
            // Не ошибка: пользователь может сознательно отключить перехват,
            // чтобы проверить систему. Но не бессмысленно — предупреждаем.
            tracing::warn!("перехват отключён для TCP и UDP: правила не применяются");
        }

        // Схема умеет только REDIRECT для TCP. Молча трактовать `tproxy` как
        // `redirect` нельзя: пользователь получил бы не то, что написал.
        if self.intercept.tcp == TcpMode::Tproxy {
            return Err(Error::ConfigInvalid(
                "intercept.tcp: tproxy для TCP не реализован — используйте redirect".into(),
            ));
        }

        self.validate_tun()?;

        // Имена outbound'ов должны быть уникальны, DIRECT — присутствовать.
        let mut names: HashSet<String> = HashSet::new();
        for ob in &self.outbounds {
            if ob.name().is_empty() {
                return Err(Error::ConfigInvalid("outbound без имени".into()));
            }
            if !names.insert(ob.name().to_string()) {
                return Err(Error::ConfigInvalid(format!(
                    "дубль имени outbound: {:?}",
                    ob.name()
                )));
            }
            ob.validate()?;
        }
        if !names.iter().any(|n| n == "DIRECT") {
            return Err(Error::ConfigInvalid(
                "в конфигурации нет outbound DIRECT — он обязателен".into(),
            ));
        }
        if names.len() == 1 && strict {
            return Err(Error::NoOutbound);
        }

        // Группы: уникальность имён, непустой список участников, участники
        // существуют (в outbound'ах или в других группах — разрешаем вложенность).
        let mut group_names: HashSet<String> = HashSet::new();
        for g in &self.groups {
            if !group_names.insert(g.name.clone()) {
                return Err(Error::ConfigInvalid(format!(
                    "дубль имени группы: {:?}",
                    g.name
                )));
            }
            if g.outbounds.is_empty() {
                return Err(Error::ConfigInvalid(format!(
                    "группа {:?} не содержит ни одного участника",
                    g.name
                )));
            }
            for member in &g.outbounds {
                if !names.contains(member) && !group_names.contains(member) {
                    return Err(Error::ConfigInvalid(format!(
                        "группа {:?} ссылается на несуществующий {:?}",
                        g.name, member
                    )));
                }
            }
        }
        // Проверяем и вложенные ссылки (после того, как собраны все имена).
        for g in &self.groups {
            for member in &g.outbounds {
                if !names.contains(member) && !group_names.contains(member) {
                    return Err(Error::ConfigInvalid(format!(
                        "группа {:?} ссылается на несуществующий {:?}",
                        g.name, member
                    )));
                }
            }
        }

        for (i, r) in self.rules.iter().enumerate() {
            let parsed = r.validate(i)?;
            if !self.policy_exists(&parsed.policy) {
                return Err(Error::ConfigInvalid(format!(
                    "правило #{} ссылается на несуществующее действие {:?}",
                    i + 1,
                    parsed.policy
                )));
            }
        }

        if self.dns.strategy == DnsStrategy::FakeIp {
            return Err(Error::ConfigInvalid(
                "dns.strategy: fake-ip не реализован — используйте redir-host: \
                 приложению возвращается настоящий адрес, а домен восстанавливается \
                 из перехваченных DNS-ответов"
                    .into(),
            ));
        }

        Ok(())
    }

    /// Проверяет поля TUN даже при `enabled: false`: опечатка в имени
    /// устройства или MTU должна всплыть при `validate`, а не в момент
    /// включения перехвата.
    fn validate_tun(&self) -> Result<()> {
        let tun = &self.tun;
        let name_ok = !tun.device.is_empty()
            && tun.device.len() < 16
            && tun.device != "lo"
            && tun
                .device
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
        if !name_ok {
            return Err(Error::ConfigInvalid(format!(
                "tun.device: недопустимое имя {:?} — до 15 символов, буквы/цифры/._-, не lo",
                tun.device
            )));
        }
        if !(576..=9000).contains(&tun.mtu) {
            return Err(Error::ConfigInvalid(format!(
                "tun.mtu: {} вне диапазона 576..9000",
                tun.mtu
            )));
        }
        let Some((addr, prefix)) = tun.address.split_once('/') else {
            return Err(Error::ConfigInvalid(format!(
                "tun.address: {:?} — нужен формат 198.18.0.1/15",
                tun.address
            )));
        };
        let addr: Ipv4Addr = addr.parse().map_err(|_| {
            Error::ConfigInvalid(format!("tun.address: {:?} — не IPv4-адрес", tun.address))
        })?;
        let prefix: u8 = prefix.parse().map_err(|_| {
            Error::ConfigInvalid(format!("tun.address: {:?} — префикс не число", tun.address))
        })?;
        if prefix > 32 {
            return Err(Error::ConfigInvalid(format!(
                "tun.address: префикс /{prefix} больше 32"
            )));
        }
        if tun.enabled {
            if self.intercept.tcp == TcpMode::Off && self.intercept.udp == UdpMode::Off {
                return Err(Error::ConfigInvalid(
                    "tun.enabled требует intercept.tcp или intercept.udp: интерфейсу нечего \
                     перехватывать"
                        .into(),
                ));
            }
            // Адрес должен быть в тестовом диапазоне или хотя бы не пересекаться
            // с типичными локальными сетями — иначе локальный трафик уедет в TUN.
            if addr.is_loopback() || addr.is_private() || addr.is_link_local() {
                tracing::warn!(
                    address = %tun.address,
                    "адрес TUN пересекается с локальными сетями: локальный трафик к этим адресам \
                     уйдёт в прокси"
                );
            }
        }
        Ok(())
    }

    fn policy_exists(&self, p: &Policy) -> bool {
        match p {
            Policy::Direct | Policy::Reject | Policy::RejectDrop | Policy::HijackDns => true,
            Policy::Named(name) => {
                self.outbounds.iter().any(|o| o.name() == name)
                    || self.groups.iter().any(|g| &g.name == name)
            }
        }
    }

    /// Имена всех исходящих соединений, включая вложенные группы — для UI.
    pub fn all_outbound_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .outbounds
            .iter()
            .map(|o| o.name().to_string())
            .collect();
        v.extend(self.groups.iter().map(|g| g.name.clone()));
        v
    }

    pub fn find_outbound(&self, name: &str) -> Option<&Outbound> {
        self.outbounds.iter().find(|o| o.name() == name)
    }

    pub fn find_group(&self, name: &str) -> Option<&GroupConfig> {
        self.groups.iter().find(|g| g.name == name)
    }
}

// ──────────────────────────────── секции ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_true")]
    pub journal: bool,
    #[serde(default)]
    pub file: Option<String>,
}

fn default_log_level() -> String {
    "info".into()
}
fn default_true() -> bool {
    true
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            journal: true,
            file: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
// Имена со знаком дефиса: `fake-ip`, `redir-host`. С `lowercase` serde
// выдало бы `fakeip`, и конфиг не прошёл бы собственную валидацию.
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum DnsStrategy {
    /// Синтетический 198.18.0.0/16 — **не реализовано**. Значение осталось
    /// в схеме, чтобы старый конфиг получил внятную ошибку с указанием на
    /// `redir-host`, а не «unknown variant».
    FakeIp,
    /// Перехватывает DNS и отдаёт настоящий адрес; соответствие «IP → домен»
    /// демон берёт из самих ответов и применяет доменные правила к
    /// последующим соединениям.
    #[default]
    RedirHost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default)]
    pub strategy: DnsStrategy,
    /// Перехватывать запросы к системному резолверу `127.0.0.53`
    /// (systemd-resolved). Без этого приложения, которые спрашивают имена
    /// через системный DNS, ходят мимо прокси: заблокированное по имени
    /// остаётся недоступным, хотя перехват включён.
    #[serde(default = "default_true")]
    pub intercept_stub: bool,
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,
    #[serde(default = "default_dns_servers")]
    pub servers: Vec<String>,
    #[serde(default = "default_dns_fallback")]
    pub fallback: Vec<String>,
}

fn default_cache_size() -> usize {
    4096
}
fn default_cache_ttl() -> u64 {
    300
}
fn default_dns_servers() -> Vec<String> {
    vec!["1.1.1.1".into(), "8.8.8.8".into()]
}
fn default_dns_fallback() -> Vec<String> {
    vec!["9.9.9.9".into(), "1.0.0.1".into()]
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            strategy: DnsStrategy::default(),
            intercept_stub: true,
            cache_size: default_cache_size(),
            cache_ttl: default_cache_ttl(),
            servers: default_dns_servers(),
            fallback: default_dns_fallback(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TcpMode {
    Redirect,
    Tproxy,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UdpMode {
    Tproxy,
    Off,
}

fn default_tcp_mode() -> TcpMode {
    TcpMode::Redirect
}
fn default_udp_mode() -> UdpMode {
    UdpMode::Tproxy
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterceptConfig {
    #[serde(default = "default_tcp_mode")]
    pub tcp: TcpMode,
    #[serde(default = "default_udp_mode")]
    pub udp: UdpMode,
    /// Перехватывать также трафик Docker-контейнеров (FORWARD-хук).
    /// Добавляется собственная цепочка `table inet pfu` с приоритетом -10,
    /// чтобы не конфликтовать с цепочкой DOCKER-USER (приоритет 0).
    #[serde(default = "default_false")]
    pub docker: bool,
    #[serde(default)]
    pub exclude_uid: Vec<u32>,
    #[serde(default = "default_exclude_ports")]
    pub exclude_ports: Vec<String>,
    #[serde(default = "default_true")]
    pub bypass_private: bool,
    #[serde(default = "default_true")]
    pub loop_protect: bool,
}

fn default_false() -> bool {
    false
}

fn default_exclude_ports() -> Vec<String> {
    vec!["22".into()]
}

impl Default for InterceptConfig {
    fn default() -> Self {
        Self {
            tcp: default_tcp_mode(),
            udp: default_udp_mode(),
            docker: default_false(),
            exclude_uid: Vec::new(),
            exclude_ports: default_exclude_ports(),
            bypass_private: true,
            loop_protect: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunConfig {
    /// Включён ли перехват через TUN. Это отдельный режим: локальный трафик
    /// уходит в устройство целиком, а не в сокет демона.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_tun_device")]
    pub device: String,
    /// MTU интерфейса. 1500 по умолчанию: больший MTU на обычной сети
    /// приводит к тому, что крупные датаграммы не проходят наружу.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Адрес интерфейса. Диапазон 198.18.0.0/15 — тестовый (RFC 2544),
    /// в реальных сетях не используется.
    #[serde(default = "default_tun_address")]
    pub address: String,
}

fn default_tun_device() -> String {
    "pfu0".into()
}
fn default_mtu() -> u16 {
    1500
}
fn default_tun_address() -> String {
    "198.18.0.1/15".into()
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            device: default_tun_device(),
            mtu: default_mtu(),
            address: default_tun_address(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoSource {
    pub kind: GeoKind,
    pub tag: String,
    pub url: String,
    /// Если задан, файл принимается только при совпадении хэша.
    #[serde(default)]
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GeoKind {
    Geoip,
    Geosite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoConfig {
    #[serde(default = "default_true")]
    pub auto_update: bool,
    #[serde(default = "default_geo_interval")]
    pub update_interval_hours: u64,
    #[serde(default)]
    pub sources: Vec<GeoSource>,
}

fn default_geo_interval() -> u64 {
    24
}

impl Default for GeoConfig {
    fn default() -> Self {
        Self {
            auto_update: true,
            update_interval_hours: default_geo_interval(),
            sources: Vec::new(),
        }
    }
}

// ──────────────────────────────── группы ────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum GroupType {
    #[default]
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupConfig {
    pub name: String,
    #[serde(default)]
    pub r#type: GroupType,
    #[serde(default)]
    pub outbounds: Vec<String>,
    #[serde(default = "default_interval")]
    pub interval_sec: u64,
    #[serde(default = "default_test_url")]
    pub url: String,
}

fn default_interval() -> u64 {
    300
}
fn default_test_url() -> String {
    "https://www.gstatic.com/generate_204".into()
}

impl GroupConfig {
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::ConfigInvalid("группа без имени".into()));
        }
        if matches!(self.r#type, GroupType::UrlTest | GroupType::Fallback)
            && self.outbounds.len() < 2
        {
            return Err(Error::ConfigInvalid(format!(
                "группа {:?} типа {:?} должна содержать минимум два outbound'а",
                self.name, self.r#type
            )));
        }
        Ok(())
    }
}

/// Ограничения скорости и числа соединений.
///
/// Есть глобальные значения (действуют на весь проксируемый трафик) и
/// переопределения для отдельных outbound'ов по имени.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Долгосрочная скорость всего проксируемого трафика, байт/сек.
    /// `None` (или 0) — не ограничено. Токен-ведро позволяет один скачок
    /// на одну секунду во всю лимитирующую скорость.
    #[serde(default)]
    pub rate_limit: Option<u64>,
    /// Максимум одновременно открытых соединений.
    #[serde(default)]
    pub max_connections: Option<u64>,
    /// Переопределения для конкретных outbound'ов — ключ — имя outbound'а.
    #[serde(default)]
    pub outbound: HashMap<String, OutboundLimit>,
}

/// Лимиты одного outbound'а. Переопределяют глобальные из `limits`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundLimit {
    #[serde(default)]
    pub rate_limit: Option<u64>,
    #[serde(default)]
    pub max_connections: Option<u64>,
}

// ──────────────────────────────── outbound'ы ────────────────────────────────

/// Именованный исходящий канал. Вариант соответствует полю `type` в YAML.
///
/// `Debug` реализован вручную (см. ниже): производный печатал пароли, UUID и
/// паролевые фразы открытым текстом, а `{:?}` уезжает в журнал и в отчёты.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Outbound {
    Direct(OutboundDirect),
    Http(OutboundHttp),
    /// `socks5h` — синоним для `socks5` с `remote_dns: true`. Понятнее
    /// пользователю, который знает эту разницу по Clash-конфигам.
    #[serde(alias = "socks5h", alias = "socks5")]
    Socks(OutboundSocks),
    Shadowsocks(OutboundShadowsocks),
    Trojan(OutboundTrojan),
    Vless(OutboundVless),
    Vmess(OutboundVmess),
    Ssh(OutboundSsh),
}

/// Значение секретного поля для `Debug`: сам секрет не печатается.
fn secret(value: &str) -> &'static str {
    if value.is_empty() {
        "<пусто>"
    } else {
        "***"
    }
}

impl std::fmt::Debug for Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Секреты не попадают в `{:?}`: этого требуют `REQ-013` и правило
        // «секретов нет в логах и артефактах». Имя, адрес, порт и транспорт
        // остаются — по ним отладка и возможна.
        match self {
            Outbound::Direct(o) => f
                .debug_struct("Outbound::Direct")
                .field("name", &o.name)
                .finish(),
            Outbound::Http(o) => f
                .debug_struct("Outbound::Http")
                .field("name", &o.name)
                .field("server", &o.server)
                .field("port", &o.port)
                .field("username", &o.username)
                .field("password", &secret(&o.password))
                .field("password_file", &o.password_file)
                .finish(),
            Outbound::Socks(o) => f
                .debug_struct("Outbound::Socks")
                .field("name", &o.name)
                .field("server", &o.server)
                .field("port", &o.port)
                .field("username", &o.username)
                .field("password", &secret(&o.password))
                .field("udp", &o.udp)
                .field("remote_dns", &o.remote_dns)
                .finish(),
            Outbound::Shadowsocks(o) => f
                .debug_struct("Outbound::Shadowsocks")
                .field("name", &o.name)
                .field("server", &o.server)
                .field("port", &o.port)
                .field("method", &o.method)
                .field("password", &secret(&o.password))
                .field("udp", &o.udp)
                .finish(),
            Outbound::Trojan(o) => f
                .debug_struct("Outbound::Trojan")
                .field("name", &o.name)
                .field("server", &o.server)
                .field("port", &o.port)
                .field("password", &secret(&o.password))
                .field("sni", &o.sni)
                .field("tls", &true)
                .finish(),
            Outbound::Vless(o) => f
                .debug_struct("Outbound::Vless")
                .field("name", &o.name)
                .field("server", &o.server)
                .field("port", &o.port)
                .field("uuid", &secret(&o.uuid))
                .field("network", &o.network)
                .field("tls", &o.tls)
                .field("sni", &o.sni)
                .finish(),
            Outbound::Vmess(o) => f
                .debug_struct("Outbound::Vmess")
                .field("name", &o.name)
                .field("server", &o.server)
                .field("port", &o.port)
                .field("uuid", &secret(&o.uuid))
                .field("network", &o.network)
                .field("tls", &o.tls)
                .field("sni", &o.sni)
                .finish(),
            Outbound::Ssh(o) => f
                .debug_struct("Outbound::Ssh")
                .field("name", &o.name)
                .field("server", &o.server)
                .field("port", &o.port)
                .field("username", &o.username)
                .field("password", &secret(&o.password))
                .field("passphrase", &secret(&o.passphrase))
                .field("key_file", &o.key_file)
                .finish(),
        }
    }
}

impl Outbound {
    pub fn name(&self) -> &str {
        match self {
            Outbound::Direct(o) => &o.name,
            Outbound::Http(o) => &o.name,
            Outbound::Socks(o) => &o.name,
            Outbound::Shadowsocks(o) => &o.name,
            Outbound::Trojan(o) => &o.name,
            Outbound::Vless(o) => &o.name,
            Outbound::Vmess(o) => &o.name,
            Outbound::Ssh(o) => &o.name,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Outbound::Direct(_) => "direct",
            Outbound::Http(_) => "http",
            Outbound::Socks(_) => "socks5",
            Outbound::Shadowsocks(_) => "shadowsocks",
            Outbound::Trojan(_) => "trojan",
            Outbound::Vless(_) => "vless",
            Outbound::Vmess(_) => "vmess",
            Outbound::Ssh(_) => "ssh",
        }
    }

    /// Умеет ли этот outbound пересылать UDP (нужно для QUIC, DNS, игр).
    pub fn supports_udp(&self) -> bool {
        match self {
            Outbound::Direct(_) => true,
            Outbound::Http(_) => false,
            Outbound::Socks(o) => o.udp,
            Outbound::Shadowsocks(o) => o.udp,
            Outbound::Trojan(o) => o.udp,
            Outbound::Vless(o) => o.udp,
            Outbound::Vmess(o) => o.udp,
            Outbound::Ssh(_) => false,
        }
    }

    /// Домен передаётся прокси как есть, без локального резолва.
    /// Для таких outbound'ов мы обязаны решать DNS удалённо, иначе течёт.
    pub fn remote_dns(&self) -> bool {
        match self {
            Outbound::Direct(_) => false,
            Outbound::Http(_) => true,
            Outbound::Socks(o) => o.remote_dns,
            Outbound::Shadowsocks(_) => true,
            Outbound::Trojan(_) => true,
            Outbound::Vless(_) => true,
            Outbound::Vmess(_) => true,
            Outbound::Ssh(_) => true,
        }
    }

    pub fn test_url(&self) -> &str {
        match self {
            Outbound::Direct(o) => o
                .test_url
                .as_deref()
                .unwrap_or("https://www.gstatic.com/generate_204"),
            Outbound::Http(o) => o
                .test_url
                .as_deref()
                .unwrap_or("https://www.gstatic.com/generate_204"),
            Outbound::Socks(o) => o
                .test_url
                .as_deref()
                .unwrap_or("https://www.gstatic.com/generate_204"),
            Outbound::Shadowsocks(o) => o
                .test_url
                .as_deref()
                .unwrap_or("https://www.gstatic.com/generate_204"),
            Outbound::Trojan(o) => o
                .test_url
                .as_deref()
                .unwrap_or("https://www.gstatic.com/generate_204"),
            Outbound::Vless(o) => o
                .test_url
                .as_deref()
                .unwrap_or("https://www.gstatic.com/generate_204"),
            Outbound::Vmess(o) => o
                .test_url
                .as_deref()
                .unwrap_or("https://www.gstatic.com/generate_204"),
            Outbound::Ssh(o) => o
                .test_url
                .as_deref()
                .unwrap_or("https://www.gstatic.com/generate_204"),
        }
    }

    fn validate(&self) -> Result<()> {
        let n = self.name();
        let host = self.server();
        if let Some(h) = host {
            if h.trim().is_empty() {
                return Err(Error::ConfigInvalid(format!(
                    "outbound {n:?}: пустой server"
                )));
            }
            if h.contains(char::is_whitespace) {
                return Err(Error::ConfigInvalid(format!(
                    "outbound {n:?}: server {:?} содержит пробелы",
                    h
                )));
            }
        }
        if let Some(p) = self.port() {
            if p == 0 {
                return Err(Error::ConfigInvalid(format!(
                    "outbound {n:?}: порт {p} вне диапазона 1-65535"
                )));
            }
        }
        match self {
            Outbound::Socks(o) => {
                if o.remote_dns && o.udp {
                    tracing::debug!("socks5h с UDP: домен уходит на прокси вместе с QUIC");
                }
            }
            Outbound::Shadowsocks(o) => {
                if !o.method_is_supported() {
                    return Err(Error::ConfigInvalid(format!(
                        "outbound {n:?}: неподдерживаемый метод шифрования {:?}",
                        o.method
                    )));
                }
                if o.password.is_empty() {
                    return Err(Error::ConfigInvalid(format!(
                        "outbound {n:?}: пустой password"
                    )));
                }
            }
            Outbound::Trojan(o) => {
                if o.password.is_empty() {
                    return Err(Error::ConfigInvalid(format!(
                        "outbound {n:?}: пустой password"
                    )));
                }
            }
            Outbound::Vless(o) => {
                o.uuid.parse::<uuid::Uuid>().map_err(|e| {
                    Error::ConfigInvalid(format!("outbound {n:?}: неверный uuid: {e}"))
                })?;
                if !o.flow.is_empty() {
                    return Err(Error::ConfigInvalid(format!(
                        "outbound {n:?}: flow={:?} требует Reality, которое не поддерживается",
                        o.flow
                    )));
                }
                if let Some(nw) = o.network.as_deref() {
                    if !matches!(nw, "tcp" | "ws") {
                        return Err(Error::ConfigInvalid(format!(
                            "outbound {n:?}: transport={nw:?} не поддерживается (tcp | ws)"
                        )));
                    }
                }
            }
            Outbound::Vmess(o) => {
                o.uuid.parse::<uuid::Uuid>().map_err(|e| {
                    Error::ConfigInvalid(format!("outbound {n:?}: неверный uuid: {e}"))
                })?;
                if o.alter_id != 0 {
                    return Err(Error::ConfigInvalid(format!(
                        "outbound {n:?}: alter_id={} не поддерживается, только AEAD-режим с alterId=0",
                        o.alter_id
                    )));
                }
                if let Some(nw) = o.network.as_deref() {
                    if !matches!(nw, "tcp" | "ws") {
                        return Err(Error::ConfigInvalid(format!(
                            "outbound {n:?}: transport={nw:?} не поддерживается (tcp | ws)"
                        )));
                    }
                }
            }
            Outbound::Ssh(o)
                if o.password.is_empty() && o.key_file.as_deref().unwrap_or("").is_empty() =>
            {
                return Err(Error::ConfigInvalid(format!(
                    "outbound {n:?}: укажите password или key_file"
                )));
            }
            _ => {}
        }
        Ok(())
    }

    fn server(&self) -> Option<&str> {
        match self {
            Outbound::Direct(_) => None,
            Outbound::Http(o) => Some(&o.server),
            Outbound::Socks(o) => Some(&o.server),
            Outbound::Shadowsocks(o) => Some(&o.server),
            Outbound::Trojan(o) => Some(&o.server),
            Outbound::Vless(o) => Some(&o.server),
            Outbound::Vmess(o) => Some(&o.server),
            Outbound::Ssh(o) => Some(&o.server),
        }
    }

    fn port(&self) -> Option<u16> {
        match self {
            Outbound::Direct(_) => None,
            Outbound::Http(o) => Some(o.port),
            Outbound::Socks(o) => Some(o.port),
            Outbound::Shadowsocks(o) => Some(o.port),
            Outbound::Trojan(o) => Some(o.port),
            Outbound::Vless(o) => Some(o.port),
            Outbound::Vmess(o) => Some(o.port),
            Outbound::Ssh(o) => Some(o.port),
        }
    }

    /// `host:port` для исходящего соединения.
    pub fn server_addr(&self) -> Result<SocketAddr> {
        use std::net::ToSocketAddrs;
        let host = self.server().ok_or_else(|| {
            Error::ConfigInvalid(format!("outbound {:?}: нет server", self.name()))
        })?;
        let port = self
            .port()
            .ok_or_else(|| Error::ConfigInvalid(format!("outbound {:?}: нет port", self.name())))?;
        let addrs: Vec<_> = (host, port).to_socket_addrs()?.collect();
        addrs
            .first()
            .copied()
            .ok_or_else(|| Error::ConfigInvalid(format!("не удалось разрешить {host}:{port}")))
    }
}

/// Поля, общие для всех outbound'ов. Вынесены в трейты, чтобы не дублировать
/// `test_url`/`test_timeout_ms` в восьми структурах.
pub trait OutboundCommon {
    fn name(&self) -> &str;
    fn test_url(&self) -> Option<&str>;
    fn test_timeout_ms(&self) -> Option<u64>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundDirect {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundHttp {
    pub name: String,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundSocks {
    pub name: String,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_true")]
    pub udp: bool,
    /// `true` — socks5h: домен уходит на прокси, локальный DNS не используется.
    #[serde(default = "default_true")]
    pub remote_dns: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundShadowsocks {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub method: String,
    pub password: String,
    #[serde(default)]
    pub plugin: String,
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_timeout_ms: Option<u64>,
}

impl OutboundShadowsocks {
    /// AEAD-методы считаются безопасными, legacy-шифры помечаем в UI.
    /// Без AEAD трафик не защищён от подмены: злоумышленник в середине пути
    /// может менять данные, оставаясь невидимым.
    pub fn method_is_aead(&self) -> bool {
        self.method.ends_with("gcm")
            || (self.method.starts_with("chacha20") && self.method.ends_with("poly1305"))
    }

    pub fn method_is_supported(&self) -> bool {
        matches!(
            self.method.as_str(),
            "chacha20-ietf-poly1305"
                | "aes-128-gcm"
                | "aes-256-gcm"
                | "chacha20"
                | "aes-128-cfb"
                | "aes-256-cfb"
                | "rc4-md5"
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundTrojan {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default)]
    pub sni: String,
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub skip_cert_verify: bool,
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_timeout_ms: Option<u64>,
}

fn default_alpn() -> Vec<String> {
    vec!["h2".into(), "http/1.1".into()]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Transport {
    #[default]
    Tcp,
    Ws,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundVless {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub skip_cert_verify: bool,
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundVmess {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default)]
    pub alter_id: u32,
    #[serde(default = "default_vmess_security")]
    pub security: String,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub skip_cert_verify: bool,
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_timeout_ms: Option<u64>,
}

fn default_vmess_security() -> String {
    "auto".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum HostKeyCheck {
    /// Принять любой новый ключ, не предупреждая (текущее поведение по умолчанию).
    #[default]
    AcceptNew,
    /// Принимать только ключи из known_hosts — новые ключи отвергаются.
    Strict,
    /// Принять новый ключ, но предупредить в логе (trust-on-first-use).
    TrustOnFirstUse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundSsh {
    pub name: String,
    pub server: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub key_file: Option<String>,
    #[serde(default)]
    pub passphrase: String,
    #[serde(default = "default_host_key_algorithms")]
    pub host_key_algorithms: Vec<String>,
    /// Режим проверки ключа хоста: strict / tofu / accept-new.
    #[serde(default)]
    pub host_key_check: HostKeyCheck,
    /// Пусть к собственному файлу known_hosts (для strict/tofu).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_hosts_file: Option<String>,
    #[serde(default = "default_ssh_keepalive")]
    pub keepalive: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_timeout_ms: Option<u64>,
}

fn default_ssh_port() -> u16 {
    22
}
fn default_ssh_keepalive() -> u64 {
    30
}
fn default_host_key_algorithms() -> Vec<String> {
    vec![
        "ssh-ed25519".into(),
        "rsa-sha2-512".into(),
        "ecdsa-sha2-nistp256".into(),
    ]
}

// ──────────────────────────────── правила ────────────────────────────────

/// Что делать с соединением.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    Direct,
    Reject,
    RejectDrop,
    HijackDns,
    Named(String),
}

/// Сериализуем в имена Clash-формата, а не в имена вариантов Rust. Иначе
/// сохранённый конфиг содержал бы `final: Direct`, и пользователь, который
/// откроет его в редакторе, увидит нечто, чего нигде не документировано.
impl Serialize for Policy {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

/// Разбор вручную, а не через `#[serde(untagged)]`: в untagged-энуме
/// единичные варианты принимают только `null`, поэтому строка `"REJECT"`
/// всегда попала бы в `Named` — и валидатор ругался бы на несуществующий
/// outbound с именем REJECT.
impl<'de> Deserialize<'de> for Policy {
    fn deserialize<D>(d: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(d)?;
        parse_policy(&raw).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Policy::Named(n) => write!(f, "{n}"),
            Policy::Direct => write!(f, "DIRECT"),
            Policy::Reject => write!(f, "REJECT"),
            Policy::RejectDrop => write!(f, "REJECT-DROP"),
            Policy::HijackDns => write!(f, "HIJACK-DNS"),
        }
    }
}

/// Тип условия правила.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// Правила пишутся как в Clash: DOMAIN-SUFFIX, а не DOMAIN_SUFFIX.
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum RuleKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    IpCidr,
    Geoip,
    Geosite,
    DstPort,
    SrcPort,
    ProcessName,
    ProcessPath,
    Uid,
    Network,
    Match,
}

impl RuleKind {
    /// Сколько полей после типа требуется в строке правила.
    /// Сколько параметров требует правило этого типа. У всех типов, кроме
    /// MATCH, ровно один.
    fn arity(&self) -> usize {
        match self {
            RuleKind::Match => 0,
            _ => 1,
        }
    }
}

/// Одно правило в Clash-подобном строковом виде. Такое представление
/// пользователю привычнее, а в исполняемый вид его компилирует
/// [`crate::engine::rules`].
///
/// В YAML это обычная строка — `DOMAIN-SUFFIX,example.com,Работа`, — но при
/// обмене через JSON IPC приходит объектом `{"raw": "..."}`. Поддерживаем
/// оба вида, чтобы одна и та же конфигурация читалась из обоих форматов.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Rule {
    Plain(String),
    Detailed { raw: String },
}

impl Rule {
    /// Исходная строка правила в любом из представлений.
    pub fn raw(&self) -> &str {
        match self {
            Rule::Plain(s) => s,
            Rule::Detailed { raw } => raw,
        }
    }
}

impl From<&str> for Rule {
    fn from(s: &str) -> Self {
        Rule::Plain(s.to_string())
    }
}

impl Rule {
    pub fn parse_str(raw: &str) -> Result<ParsedRule> {
        Self::parse(raw)
    }

    pub fn parse(raw: &str) -> Result<ParsedRule> {
        let parts: Vec<&str> = raw.split(',').map(str::trim).collect();
        if parts.is_empty() || parts[0].is_empty() {
            return Err(Error::ConfigInvalid(format!("пустое правило: {raw:?}")));
        }
        // Без запятой негде взять действие. Раньше здесь был `parts[1..0]`,
        // и `rules: [MATCH, Битый]` (список из двух строк в YAML) ронял
        // демон целиком вместо сообщения об ошибке.
        if parts.len() < 2 {
            return Err(Error::ConfigInvalid(format!(
                "в правиле {raw:?} нет действия: ожидается ТИП,ПАРАМЕТРЫ,ДЕЙСТВИЕ"
            )));
        }
        let kind_str = parts[0].to_ascii_uppercase();
        let kind: RuleKind = serde_yaml::from_str(&kind_str).map_err(|_| {
            Error::ConfigInvalid(format!("неизвестный тип правила {:?} в {raw:?}", parts[0]))
        })?;

        // Последнее непустое поле — действие, остальные между — параметры типа.
        let last = parts.len() - 1;
        let policy_raw = parts[last];
        let policy = parse_policy(policy_raw)?;
        let args: Vec<String> = parts[1..last].iter().map(|s| s.to_string()).collect();

        if args.len() < kind.arity() {
            return Err(Error::ConfigInvalid(format!(
                "правилу {:?} не хватает параметров: нужно {}, есть {}",
                kind_str,
                kind.arity(),
                args.len()
            )));
        }
        if matches!(kind, RuleKind::Match) && !args.is_empty() {
            return Err(Error::ConfigInvalid(format!(
                "правило MATCH не принимает параметров: {raw:?}"
            )));
        }
        if matches!(kind, RuleKind::DstPort | RuleKind::SrcPort) && args.len() != 1 {
            return Err(Error::ConfigInvalid(format!(
                "правило {kind_str} принимает ровно один параметр: {raw:?}"
            )));
        }

        Ok(ParsedRule { kind, args, policy })
    }

    /// Разбирает правило и подставляет номер строки в сообщение об ошибке.
    pub fn validate(&self, index: usize) -> Result<ParsedRule> {
        Self::parse(self.raw())
            .map_err(|e| Error::ConfigInvalid(format!("правило #{}: {}", index + 1, e)))
    }
}

pub fn parse_policy(s: &str) -> Result<Policy> {
    match s.to_ascii_uppercase().as_str() {
        "DIRECT" => Ok(Policy::Direct),
        "REJECT" => Ok(Policy::Reject),
        "REJECT-DROP" => Ok(Policy::RejectDrop),
        "HIJACK-DNS" => Ok(Policy::HijackDns),
        _ if s.is_empty() => Err(Error::ConfigInvalid("пустое действие правила".into())),
        _ => Ok(Policy::Named(s.to_string())),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRule {
    pub kind: RuleKind,
    pub args: Vec<String>,
    pub policy: Policy,
}

impl ParsedRule {
    pub fn arg(&self, i: usize) -> &str {
        self.args.get(i).map(String::as_str).unwrap_or("")
    }
}

// ──────────────────────────── подстановка переменных ───────────────────────

/// Имена `${VAR}`, для которых в `env` нет значения и нет `:-default`.
///
/// Проверка нужна до подстановки: `expand_env` подставляет пустую строку, и
/// секрет молча становится пустым. Для чтения конфига (`load_for_read`,
/// `config.get`) это допустимо, для применения — нет.
pub fn missing_env_refs(text: &str, env: &HashMap<String, String>) -> Vec<String> {
    let mut missing: Vec<String> = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            break;
        };
        let expr = &after[..end];
        let (name, has_default) = match expr.split_once(":-") {
            Some((name, _)) => (name, true),
            None => (expr, false),
        };
        let name = name.trim();
        if !name.is_empty()
            && !has_default
            && !env.contains_key(name)
            && !missing.iter().any(|known| known == name)
        {
            missing.push(name.to_string());
        }
        rest = &after[end + 1..];
    }
    missing
}

/// Подставляет `${VAR}` и `${VAR:-default}` из карты. Неизвестная переменная
/// без default подставляется пустой строкой; `Config::parse` такую ситуацию
/// отвергает через [`missing_env_refs`], чтобы не отправить в коннект пустой
/// пароль вместо секрета.
pub fn expand_env(text: &str, env: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '$' && i + 1 < bytes.len() && bytes[i + 1] == '{' {
            if let Some(end) = bytes[i + 2..].iter().position(|c| *c == '}') {
                let name: String = bytes[i + 2..i + 2 + end].iter().collect();
                let (key, default) = match name.split_once(":-") {
                    Some((k, d)) => (k.to_string(), Some(d.to_string())),
                    None => (name, None),
                };
                let replacement = env.get(&key).cloned().or(default).unwrap_or_default();
                out.push_str(&replacement);
                i = i + 2 + end + 1;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Читает `/etc/proxy-for-ubuntu/env` в формате `KEY=value`. Строки с `#` и
/// пустые игнорируются.
pub fn read_env_file(path: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return map;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches('"').trim_matches('\'');
            map.insert(k.trim().to_string(), v.to_string());
        }
    }
    map
}

// ───────────────────────────────── тесты ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn parses_minimal_config() {
        let yaml = r#"
outbounds:
  - name: DIRECT
    type: direct
  - name: SOCKS
    type: socks5h
    server: 1.2.3.4
    port: 1080
rules:
  - DOMAIN-SUFFIX,example.com,SOCKS
  - MATCH,DIRECT
"#;
        let cfg = Config::parse(yaml, &HashMap::new()).unwrap();
        assert_eq!(cfg.outbounds.len(), 2);
        assert_eq!(cfg.rules.len(), 2);
        assert_eq!(cfg.outbounds[1].kind(), "socks5");
        assert!(cfg.outbounds[1].remote_dns());
    }

    #[test]
    fn tun_defaults_are_safe() {
        let cfg = Config::default();
        assert!(!cfg.tun.enabled, "TUN по умолчанию выключен");
        assert_eq!(cfg.tun.device, "pfu0");
        // 1500, а не 9000: крупная датаграмма в обычной сети не пролезет.
        assert_eq!(cfg.tun.mtu, 1500);
        assert_eq!(cfg.tun.address, "198.18.0.1/15");
        cfg.validate_for_read().unwrap();
    }

    #[test]
    fn load_for_read_sees_tun_in_a_direct_only_config() {
        // Свежая установка: единственный outbound — DIRECT. Строгий `load`
        // такой конфиг отвергает, поэтому `--check` обязан читать
        // `load_for_read`: иначе `unwrap_or(false)` сообщает «TUN выключен»
        // при `tun.enabled: true` и прячет отсутствующий /dev/net/tun.
        let yaml = "tun:\n  enabled: true\noutbounds:\n  - {name: DIRECT, type: direct}\n";
        let p = std::env::temp_dir().join(format!("pfu-tun-{}.yaml", std::process::id()));
        std::fs::write(&p, yaml).unwrap();
        assert!(Config::load(&p, &HashMap::new()).is_err());
        let cfg = Config::load_for_read(&p, &HashMap::new()).unwrap();
        let _ = std::fs::remove_file(&p);
        assert!(cfg.tun.enabled);
    }

    #[test]
    fn tun_requires_interception() {
        let yaml = r#"
tun:
  enabled: true
intercept:
  tcp: off
  udp: off
outbounds:
  - {name: DIRECT, type: direct}
"#;
        let err = Config::parse(yaml, &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("tun.enabled"), "{err}");
    }

    #[test]
    fn tun_fields_are_validated() {
        for (block, needle) in [
            ("enabled: false\n  device: \"\"", "tun.device"),
            ("enabled: false\n  mtu: 100", "tun.mtu"),
            ("enabled: false\n  address: 198.18.0.1", "tun.address"),
            ("enabled: false\n  address: 10.0.0.1/40", "префикс"),
        ] {
            let yaml = format!("tun:\n  {block}\noutbounds:\n  - {{name: DIRECT, type: direct}}\n");
            let err = Config::parse(&yaml, &HashMap::new()).unwrap_err();
            assert!(err.to_string().contains(needle), "{yaml}: {err}");
        }
    }

    #[test]
    fn removed_strict_route_is_rejected() {
        // Поле убрано вместе с TUN-реализацией: оно никогда ничего не делало,
        // а молча игнорировать настройку хуже, чем отказать.
        let yaml = r#"
tun:
  enabled: false
  strict_route: true
outbounds:
  - {name: DIRECT, type: direct}
"#;
        let err = Config::parse(yaml, &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("strict_route"), "{err}");
    }

    #[test]
    fn tun_block_round_trips() {
        let yaml = r#"
tun:
  enabled: true
  device: pfu9
  mtu: 1400
  address: 172.19.0.1/30
intercept:
  tcp: redirect
  udp: off
outbounds:
  - {name: DIRECT, type: direct}
  - {name: X, type: http, server: a, port: 80}
"#;
        let cfg = Config::parse(yaml, &HashMap::new()).unwrap();
        assert!(cfg.tun.enabled);
        assert_eq!(cfg.tun.device, "pfu9");
        assert_eq!(cfg.tun.mtu, 1400);
        assert_eq!(cfg.tun.address, "172.19.0.1/30");
        let back = serde_yaml::to_string(&cfg).unwrap();
        assert!(back.contains("address: 172.19.0.1/30"));
        assert!(!back.contains("strict_route"));
    }

    #[test]
    fn fake_ip_is_rejected_with_hint_to_redir_host() {
        let yaml = r#"
dns:
  strategy: fake-ip
tun:
  enabled: true
intercept:
  tcp: redirect
  udp: off
outbounds:
  - {name: DIRECT, type: direct}
  - {name: X, type: http, server: a, port: 80}
"#;
        // Настройка, которая ничего не делает, хуже отказа: fake-ip не
        // реализован, и конфиг обязан это сказать, а не притворяться.
        let err = Config::parse(yaml, &HashMap::new()).unwrap_err();
        assert!(
            err.to_string().contains("redir-host"),
            "в ошибке нет подсказки: {err}"
        );
    }

    #[test]
    fn rejects_unknown_field() {
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: X, type: http, server: a, port: 80, typo_field: 1}
"#;
        let err = Config::parse(yaml, &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("typo_field"), "{err}");
    }

    #[test]
    fn rejects_rule_pointing_at_unknown_outbound() {
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: SOCKS, type: socks5, server: 1.2.3.4, port: 1080}
rules:
  - DOMAIN,example.com,НЕТ_ТАКОГО
"#;
        let err = Config::parse(yaml, &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("НЕТ_ТАКОГО"), "{err}");
    }

    #[test]
    fn rejects_bad_port() {
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: SOCKS, type: socks5, server: 1.2.3.4, port: 70000}
"#;
        assert!(Config::parse(yaml, &HashMap::new()).is_err());
    }

    #[test]
    fn expands_env_vars() {
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: S, type: http, server: 1.2.3.4, port: 8080, username: u, password: "${PW}"}
rules: []
"#;
        let cfg = Config::parse(yaml, &env(&[("PW", "s3cret")])).unwrap();
        match &cfg.outbounds[1] {
            Outbound::Http(o) => assert_eq!(o.password, "s3cret"),
            _ => panic!("ожидался http"),
        }
    }

    #[test]
    fn expands_env_with_default() {
        let e = env(&[]);
        assert_eq!(expand_env("a=${NOPE:-fallback}b", &e), "a=fallbackb");
        assert_eq!(expand_env("a=${NOPE}b", &e), "a=b");
        assert_eq!(expand_env("a=$NOPE", &e), "a=$NOPE");
        assert_eq!(expand_env("no vars", &e), "no vars");
    }

    #[test]
    fn debug_output_never_prints_secrets() {
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: HTTP, type: http, server: 1.2.3.4, port: 8080, username: u, password: "http-secret"}
  - {name: SS, type: shadowsocks, server: 5.6.7.8, port: 8388, method: chacha20-ietf-poly1305, password: "ss-secret"}
  - {name: VLESS, type: vless, server: a.example, port: 443, uuid: "11111111-2222-3333-4444-555555555555"}
  - {name: SSH, type: ssh, server: b.example, username: root, password: "ssh-secret"}
"#;
        let cfg = Config::parse(yaml, &env(&[])).expect("конфиг должен разобраться");
        let dump = format!("{cfg:?}");
        for secret in [
            "http-secret",
            "ss-secret",
            "11111111-2222-3333-4444-555555555555",
            "ssh-secret",
        ] {
            assert!(
                !dump.contains(secret),
                "секрет {secret:?} попал в Debug: {dump}"
            );
        }
        // Отладка без несекретных полей бесполезна — они должны остаться.
        assert!(dump.contains("1.2.3.4"), "{dump}");
        assert!(dump.contains("VLESS"), "{dump}");
        assert!(
            dump.contains("***"),
            "метка редактирования отсутствует: {dump}"
        );
    }

    #[test]
    fn missing_env_variable_without_default_is_an_error() {
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: S, type: http, server: 1.2.3.4, port: 8080, username: u, password: "${SMTP_PASSWORD}"}
"#;
        let err = Config::parse(yaml, &env(&[])).expect_err("без значения — ошибка");
        let text = err.to_string();
        assert!(text.contains("SMTP_PASSWORD"), "{text}");
        assert!(
            !text.contains("${SMTP_PASSWORD}"),
            "сообщение повторяет выражение вместо имени переменной: {text}"
        );

        // Значение по умолчанию — законный способ обойтись без env-файла.
        let with_default = yaml.replace("${SMTP_PASSWORD}", "${SMTP_PASSWORD:-fallback}");
        let cfg = Config::parse(&with_default, &env(&[])).expect("default допустим");
        match &cfg.outbounds[1] {
            Outbound::Http(o) => assert_eq!(o.password, "fallback"),
            other => panic!("ожидался http, получено {other:?}"),
        }
    }

    #[test]
    fn missing_env_refs_lists_each_name_once() {
        let text = "a: ${A} b: ${B} c: ${A} d: ${C:-x} e: $NOT_A_REF";
        assert_eq!(
            missing_env_refs(text, &env(&[("B", "1")])),
            vec!["A".to_string()]
        );
    }

    #[test]
    fn rejects_tcp_tproxy_mode() {
        // Режим есть в схеме, но в коде TCP всегда REDIRECT: принять и
        // проигнорировать его — хуже, чем отказать.
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: S, type: socks5, server: 1.2.3.4, port: 1080}
intercept: {tcp: tproxy}
"#;
        let err = Config::parse(yaml, &HashMap::new()).unwrap_err();
        assert!(
            err.to_string().contains("tproxy"),
            "неожиданная ошибка: {err}"
        );
    }

    #[test]
    fn dns_strategy_uses_hyphens() {
        // Регрессия: `rename_all = "lowercase"` давал `fakeip`, и собственный
        // конфиг по умолчанию переставал проходить валидацию.
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: S, type: socks5h, server: 1.2.3.4, port: 1080}
dns: {strategy: redir-host}
intercept: {udp: tproxy}
"#;
        let c = Config::parse(yaml, &HashMap::new()).unwrap();
        assert_eq!(c.dns.strategy, DnsStrategy::RedirHost);
        assert!(c.to_yaml().unwrap().contains("redir-host"));
    }

    #[test]
    fn dns_defaults_to_redir_host() {
        // Стратегия по умолчанию обязана быть той, которая работает.
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: S, type: socks5h, server: 1.2.3.4, port: 1080}
"#;
        let c = Config::parse(yaml, &HashMap::new()).unwrap();
        assert_eq!(c.dns.strategy, DnsStrategy::RedirHost);
    }

    #[test]
    fn reject_policy_is_not_read_as_outbound_name() {
        // Регрессия: при `untagged` строковый вариант шёл первым, и «REJECT»
        // превращался в имя outbound'а, которого нет.
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: S, type: socks5, server: 1.2.3.4, port: 1080}
rules:
  - DOMAIN,ads.example,REJECT
  - MATCH,DIRECT
final: DIRECT
"#;
        let c = Config::parse(yaml, &HashMap::new()).unwrap();
        assert_eq!(c.rules[0].validate(0).unwrap().policy, Policy::Reject);
        assert_eq!(c.final_policy, Policy::Direct);
    }

    #[test]
    fn rule_without_action_is_an_error_not_a_panic() {
        // Регрессия: `rules: [MATCH, Битый]` даёт две строки без запятых,
        // и разбор падал на `parts[1..0]`.
        for raw in ["MATCH", "", ",", "  ,  "] {
            assert!(
                Rule::parse(raw).is_err(),
                "правило {raw:?} должно отвергаться"
            );
        }
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: S, type: socks5, server: 1.2.3.4, port: 1080}
rules: [MATCH, Битый]
"#;
        let e = Config::parse(yaml, &HashMap::new()).unwrap_err();
        assert!(e.to_string().contains("правило"), "{e}");
    }

    #[test]
    fn policy_serializes_as_clash_names() {
        use crate::config::Policy;
        for (p, want) in [
            (Policy::Direct, "\"DIRECT\""),
            (Policy::Reject, "\"REJECT\""),
            (Policy::RejectDrop, "\"REJECT-DROP\""),
            (Policy::HijackDns, "\"HIJACK-DNS\""),
        ] {
            let got = serde_json::to_string(&p).unwrap();
            assert_eq!(got, want, "сериализация {:?} дала {got}", p);
        }
        assert_eq!(
            serde_json::to_string(&Policy::Named("Работа".into())).unwrap(),
            "\"Работа\""
        );
    }

    #[test]
    fn rule_parsing() {
        let r = Rule::parse("DOMAIN-SUFFIX,example.com,REJECT").unwrap();
        assert_eq!(r.kind, RuleKind::DomainSuffix);
        assert_eq!(r.args, vec!["example.com"]);
        assert_eq!(r.policy, Policy::Reject);

        let r = Rule::parse("MATCH,DIRECT").unwrap();
        assert_eq!(r.kind, RuleKind::Match);
        assert_eq!(r.policy, Policy::Direct);

        let r = Rule::parse("DST-PORT,1000-2000,Мой VPS").unwrap();
        assert_eq!(r.kind, RuleKind::DstPort);
        assert_eq!(r.policy, Policy::Named("Мой VPS".into()));

        assert!(Rule::parse("ДОМЕН,x,DIRECT").is_err());
        assert!(Rule::parse("MATCH,x,DIRECT").is_err());
        assert!(Rule::parse("DST-PORT,DIRECT").is_err());
    }

    #[test]
    fn vless_rejects_reality_flow() {
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: V, type: vless, server: a.example, port: 443,
     uuid: "b831381d-6324-4d53-ad4f-8cda48b30811", flow: xtls-rprx-vision}
"#;
        let err = Config::parse(yaml, &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("Reality"), "{err}");
    }

    #[test]
    fn vmess_rejects_nonzero_alter_id() {
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: V, type: vmess, server: a.example, port: 443,
     uuid: "b831381d-6324-4d53-ad4f-8cda48b30811", alter_id: 4}
"#;
        assert!(Config::parse(yaml, &HashMap::new()).is_err());
    }

    #[test]
    fn only_direct_is_rejected_for_apply_but_accepted_for_read() {
        // Сразу после установки прокси ещё нет. Для apply это ошибка,
        // а для показа конфигурации — обычное состояние.
        let yaml = "outbounds:\n  - {name: DIRECT, type: direct}\n";
        let strict = Config::parse(yaml, &HashMap::new());
        assert!(
            matches!(strict, Err(Error::NoOutbound)),
            "apply должен отвергнуть"
        );

        let cfg = Config::default();
        cfg.validate_for_read().expect("чтение должно проходить");
    }

    #[test]
    fn duplicate_outbound_names_rejected() {
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: X, type: socks5, server: 1.2.3.4, port: 1}
  - {name: X, type: socks5, server: 1.2.3.5, port: 2}
"#;
        assert!(Config::parse(yaml, &HashMap::new()).is_err());
    }

    #[test]
    fn roundtrip_yaml() {
        // Дефолтный конфиг с одним DIRECT невалиден — для проверки сериализации
        // добавляем второй outbound.
        let mut cfg = Config::default();
        cfg.outbounds.push(Outbound::Socks(OutboundSocks {
            name: "S".into(),
            server: "1.2.3.4".into(),
            port: 1080,
            username: String::new(),
            password: String::new(),
            udp: true,
            remote_dns: true,
            test_url: None,
            test_timeout_ms: None,
        }));
        cfg.rules = vec![Rule::Plain("DOMAIN,example.com,S".into())];
        let yaml = cfg.to_yaml().unwrap();
        assert!(
            yaml.contains("DOMAIN,example.com,S"),
            "правило должно сериализоваться строкой"
        );
        let back = Config::parse(&yaml, &HashMap::new()).unwrap();
        assert_eq!(back.outbounds.len(), cfg.outbounds.len());
        assert_eq!(back.final_policy, Policy::Direct);
    }

    #[test]
    fn read_env_file_parses_and_skips_comments() {
        let p = std::env::temp_dir().join(format!("pfu-env-{}", std::process::id()));
        std::fs::write(&p, "# comment\nA=1\nB = \"two\"\n\nbad_line\n").unwrap();
        let m = read_env_file(&p);
        assert_eq!(m.get("A").map(String::as_str), Some("1"));
        assert_eq!(m.get("B").map(String::as_str), Some("two"));
        assert_eq!(m.len(), 2);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn parses_traffic_limits() {
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: Работа, type: socks5, server: 1.2.3.4, port: 1080}
limits:
  rate_limit: 1048576
  max_connections: 50
  outbound:
    Работа:
      rate_limit: 524288
      max_connections: 10
"#;
        let cfg = Config::parse(yaml, &HashMap::new()).unwrap();
        assert_eq!(cfg.limits.rate_limit, Some(1_048_576));
        assert_eq!(cfg.limits.max_connections, Some(50));
        let w = cfg
            .limits
            .outbound
            .get("Работа")
            .expect("лимит для outbound 'Работа'");
        assert_eq!(w.rate_limit, Some(524_288));
        assert_eq!(w.max_connections, Some(10));
        assert!(!cfg.limits.outbound.contains_key("DIRECT"));
    }

    #[test]
    fn unknown_limit_field_is_rejected() {
        let yaml = r#"
outbounds:
  - {name: DIRECT, type: direct}
limits:
  rate_limit: 1
  nope: 2
"#;
        assert!(Config::parse(yaml, &HashMap::new()).is_err());
    }
}

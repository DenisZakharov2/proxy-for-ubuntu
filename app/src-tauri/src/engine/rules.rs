//! Rule engine: превращает список правил из конфига в исполняемую форму.
//!
//! Скомпилированные правила раскладываются по типам, чтобы на пакет не
//! парсить строки. Внутри типа — либо HashSet для точных значений, либо
//! линейный список с ранним выходом. Для тысяч правил одного типа
//! (`GEOSITE` по адресам, например) включается бинарный поиск по
//! отсортированному вектору.
//!
//! Порядок правил сохраняется: правило с меньшим индексом проверяется раньше
//! независимо от типа. Именно это делает поведение предсказуемым для
//! пользователя, привыкшего к Clash.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::{GeoKind, ParsedRule, Policy, Rule, RuleKind};
use crate::engine::geo::GeoRegistry;
use crate::error::{Error, Result};

/// Всё, что известно о соединении на момент принятия решения.
#[derive(Debug, Clone, Default)]
pub struct Flow {
    /// Настоящий получатель (из `SO_ORIGINAL_DST` при redirect).
    pub dst_ip: Option<IpAddr>,
    pub dst_port: u16,
    pub src_port: u16,
    pub is_tcp: bool,
    pub uid: u32,
    /// Имя процесса, если удалось определить по inode сокета.
    pub process: Option<String>,
    /// Домен: из DNS-запроса, TLS SNI или HTTP Host.
    pub domain: Option<String>,
    /// Признак, что домен уже известен (а не выдуман): влияет на то, можно
    /// ли доверять IP-правилам.
    pub domain_confident: bool,
}

impl Flow {
    pub fn is_udp(&self) -> bool {
        !self.is_tcp
    }

    pub fn network(&self) -> &'static str {
        if self.is_tcp {
            "tcp"
        } else {
            "udp"
        }
    }
}

/// Что нужно outbound'у, чтобы установить соединение.
#[derive(Debug, Clone)]
pub struct Target {
    /// Домен, если известен. Прокси с `remote_dns` получит его как есть.
    pub host: String,
    pub port: u16,
    pub is_tcp: bool,
}

impl Target {
    pub fn from_flow(flow: &Flow) -> Self {
        let host = flow
            .domain
            .clone()
            .or_else(|| flow.dst_ip.map(|ip| ip.to_string()))
            .unwrap_or_default();
        Self {
            host,
            port: flow.dst_port,
            is_tcp: flow.is_tcp,
        }
    }

    pub fn key(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Решение движка: куда идти и что попутно записать в статистику.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Соединение через outbound с указанным именем.
    Proxy(String),
    Direct,
    /// Закрыть сразу, ответив RST / ICMP unreachable.
    Reject,
    /// Молча выбросить пакеты — соединение «висит» до таймаута.
    RejectDrop,
    /// Отдать домен нашему резолверу (правило `HIJACK-DNS`).
    HijackDns,
}

impl Decision {
    pub fn from_policy(p: &Policy) -> Self {
        match p {
            Policy::Direct => Decision::Direct,
            Policy::Reject => Decision::Reject,
            Policy::RejectDrop => Decision::RejectDrop,
            Policy::HijackDns => Decision::HijackDns,
            Policy::Named(n) if n == "DIRECT" => Decision::Direct,
            Policy::Named(n) => Decision::Proxy(n.clone()),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Decision::Direct => "DIRECT".into(),
            Decision::Reject => "REJECT".into(),
            Decision::RejectDrop => "REJECT-DROP".into(),
            Decision::HijackDns => "HIJACK-DNS".into(),
            Decision::Proxy(n) => n.clone(),
        }
    }
}

/// Скомпилированное правило одного типа.
#[derive(Debug)]
enum Compiled {
    Domain {
        set: HashSet<String>,
        policy: Policy,
    },
    DomainSuffix {
        list: Vec<String>,
        policy: Policy,
    },
    DomainKeyword {
        list: Vec<String>,
        policy: Policy,
    },
    DomainRegex {
        re: regex::Regex,
        policy: Policy,
    },
    Cidr {
        nets: Vec<ipnet::IpNet>,
        policy: Policy,
    },
    /// Ссылка на загруженный geo-набор. `None` если набор не скачан — правило
    /// молча не срабатывает, о чём мы предупредили при загрузке реестра.
    /// `tag` хранится для диагностики: по нему в логе видно, какого именно
    /// набора не хватает.
    Geo {
        kind: GeoKind,
        #[allow(dead_code)]
        tag: String,
        handle: Option<Arc<crate::engine::geo::GeoSetHandle>>,
        policy: Policy,
    },
    Port {
        /// `u16::MAX` в списке означает «443 и выше» для правил вида `1000+`.
        set: HashSet<u16>,
        ranges: Vec<(u16, u16)>,
        policy: Policy,
    },
    Process {
        set: HashSet<String>,
        policy: Policy,
    },
    Uid {
        set: HashSet<u32>,
        policy: Policy,
    },
    Network {
        tcp: Option<bool>,
        policy: Policy,
    },
    Match {
        policy: Policy,
    },
}

#[derive(Debug)]
struct Entry {
    compiled: Compiled,
    /// Исходная строка — для журнала и экрана «активные правила».
    raw: String,
}

/// Неизменяемый скомпилированный набор правил. Подменяется целиком при
/// перезагрузке конфига, поэтому читается без блокировок.
#[derive(Debug)]
pub struct RuleSet {
    entries: Vec<Entry>,
    final_decision: Decision,
}

impl RuleSet {
    /// Компилирует правила. `geo` может быть пустым — тогда GEOIP/GEOSITE
    /// скомпилируются в заглушки и будут логировать предупреждение при первом
    /// же обращении, вместо того чтобы уронить весь движок.
    pub fn compile(rules: &[Rule], final_policy: &Policy, geo: &GeoRegistry) -> Result<Self> {
        let mut entries = Vec::with_capacity(rules.len());
        for rule in rules {
            let parsed = Rule::parse(rule.raw())?;
            let compiled = compile_one(&parsed, geo, rules, rule.raw())?;
            entries.push(Entry {
                compiled,
                raw: rule.raw().to_string(),
            });
        }
        Ok(Self {
            entries,
            final_decision: Decision::from_policy(final_policy),
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Основная точка входа: первое совпавшее правило решает.
    pub fn decide(&self, flow: &Flow) -> (Decision, Option<usize>) {
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.matches(flow) {
                return (decision_of(&entry.compiled), Some(i));
            }
        }
        (self.final_decision.clone(), None)
    }

    pub fn final_decision(&self) -> &Decision {
        &self.final_decision
    }

    /// Правила, чьи наборы не загрузились. GUI показывает их отдельным
    /// жёлтым блоком: правило есть, но не сработает.
    pub fn missing_geo(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|e| matches!(&e.compiled, Compiled::Geo { handle: None, .. }))
            .map(|e| e.raw.clone())
            .collect()
    }

    /// Кэш решений по ключу `host:port`. Реальный трафик бьёт в одни и те же
    /// хосты постоянно, а разбор SNI и прогон по правилам — не бесплатный.
    pub fn decide_cached(
        &self,
        flow: &Flow,
        cache: &mut std::collections::HashMap<String, (Decision, Option<usize>)>,
    ) -> (Decision, Option<usize>) {
        if let Some(hit) = cache.get(&flow_key(flow)) {
            return hit.clone();
        }
        let d = self.decide(flow);
        if cache.len() < 8192 {
            cache.insert(flow_key(flow), d.clone());
        }
        d
    }
}

fn flow_key(flow: &Flow) -> String {
    match (&flow.domain, flow.dst_ip) {
        (Some(d), _) => format!("d:{d}:{}", flow.dst_port),
        (None, Some(ip)) => format!("i:{ip}:{}", flow.dst_port),
        _ => format!("p:{}", flow.dst_port),
    }
}

fn decision_of(c: &Compiled) -> Decision {
    match c {
        Compiled::Domain { policy, .. }
        | Compiled::DomainSuffix { policy, .. }
        | Compiled::DomainKeyword { policy, .. }
        | Compiled::DomainRegex { policy, .. }
        | Compiled::Cidr { policy, .. }
        | Compiled::Geo { policy, .. }
        | Compiled::Port { policy, .. }
        | Compiled::Process { policy, .. }
        | Compiled::Uid { policy, .. }
        | Compiled::Network { policy, .. }
        | Compiled::Match { policy } => Decision::from_policy(policy),
    }
}

impl Entry {
    fn matches(&self, flow: &Flow) -> bool {
        match &self.compiled {
            Compiled::Match { .. } => true,

            Compiled::Domain { set, .. } => match &flow.domain {
                Some(d) => set.contains(d),
                None => false,
            },

            Compiled::DomainSuffix { list, .. } => match &flow.domain {
                Some(d) => list.iter().any(|s| domain_suffix_match(d, s)),
                None => false,
            },

            Compiled::DomainKeyword { list, .. } => match &flow.domain {
                Some(d) => list.iter().any(|k| d.contains(k.as_str())),
                None => false,
            },

            Compiled::DomainRegex { re, .. } => match &flow.domain {
                Some(d) => re.is_match(d),
                None => false,
            },

            Compiled::Cidr { nets, .. } => match flow.dst_ip {
                Some(ip) => nets.iter().any(|n| n.contains(&ip)),
                None => false,
            },

            Compiled::Geo { handle, kind, .. } => {
                let Some(h) = handle else { return false };
                let entries = h.entries();
                match (kind, &flow.domain, flow.dst_ip) {
                    // GEOSITE: смотрим на домен.
                    (GeoKind::Geosite, Some(d), _) => entries.iter().any(|e| e.matches_domain(d)),
                    // GEOIP: смотрим на адрес.
                    (GeoKind::Geoip, _, Some(ip)) => entries.iter().any(|e| e.contains_ip(ip)),
                    _ => false,
                }
            }

            Compiled::Port { set, ranges, .. } => {
                set.contains(&flow.dst_port)
                    || ranges
                        .iter()
                        .any(|(a, b)| (*a..=*b).contains(&flow.dst_port))
            }

            Compiled::Process { set, .. } => match &flow.process {
                Some(p) => {
                    let base = p.rsplit('/').next().unwrap_or(p);
                    set.contains(p) || set.contains(base)
                }
                None => false,
            },

            Compiled::Uid { set, .. } => set.contains(&flow.uid),

            Compiled::Network { tcp, .. } => match tcp {
                Some(want) => *want == flow.is_tcp,
                None => true,
            },
        }
    }
}

/// `example.com` должен матчить `a.example.com`, но не `notexample.com`.
fn domain_suffix_match(domain: &str, suffix: &str) -> bool {
    if domain == suffix {
        return true;
    }
    domain.len() > suffix.len()
        && domain.ends_with(suffix)
        && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
}

fn compile_one(
    parsed: &ParsedRule,
    geo: &GeoRegistry,
    _all: &[Rule],
    raw: &str,
) -> Result<Compiled> {
    use RuleKind::*;
    let policy = parsed.policy.clone();
    Ok(match parsed.kind {
        Match => Compiled::Match { policy },

        Domain => Compiled::Domain {
            set: parsed.args.iter().map(|a| a.to_ascii_lowercase()).collect(),
            policy,
        },

        DomainSuffix => Compiled::DomainSuffix {
            list: parsed.args.iter().map(|a| a.to_ascii_lowercase()).collect(),
            policy,
        },

        DomainKeyword => Compiled::DomainKeyword {
            list: parsed.args.iter().map(|a| a.to_ascii_lowercase()).collect(),
            policy,
        },

        DomainRegex => {
            let pattern = parsed.arg(0);
            let re = regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map_err(|e| Error::ConfigInvalid(format!("правило {raw:?}: плохое regex: {e}")))?;
            Compiled::DomainRegex { re, policy }
        }

        IpCidr => {
            let mut nets = Vec::new();
            for a in &parsed.args {
                let net = a.parse::<ipnet::IpNet>().map_err(|e| {
                    Error::ConfigInvalid(format!("правило {raw:?}: не CIDR {a:?}: {e}"))
                })?;
                nets.push(net);
            }
            Compiled::Cidr { nets, policy }
        }

        Geoip | Geosite => {
            let kind = if parsed.kind == Geoip {
                GeoKind::Geoip
            } else {
                GeoKind::Geosite
            };
            let tag = parsed.arg(0).to_string();
            let handle = geo.get(kind, &tag);
            if handle.is_none() {
                tracing::warn!(rule = raw, ?kind, %tag, "geo-набор не загружен, правило не сработает");
            }
            Compiled::Geo {
                kind,
                tag,
                handle,
                policy,
            }
        }

        DstPort | SrcPort => {
            let (mut set, mut ranges) = (HashSet::new(), Vec::new());
            for a in &parsed.args {
                for part in a.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    if let Some((lo, hi)) = part.split_once('-') {
                        let lo: u16 = lo.trim().parse().map_err(|e| {
                            Error::ConfigInvalid(format!("правило {raw:?}: порт {part:?}: {e}"))
                        })?;
                        let hi: u16 = hi.trim().parse().map_err(|e| {
                            Error::ConfigInvalid(format!("правило {raw:?}: порт {part:?}: {e}"))
                        })?;
                        if lo > hi {
                            return Err(Error::ConfigInvalid(format!(
                                "правило {raw:?}: диапазон {lo}-{hi} перевёрнут"
                            )));
                        }
                        ranges.push((lo, hi));
                    } else if let Some(base) = part.strip_suffix('+') {
                        // Форма `1000+` — «порт 1000 и выше».
                        let lo: u16 = base.trim().parse().map_err(|e| {
                            Error::ConfigInvalid(format!("правило {raw:?}: порт {part:?}: {e}"))
                        })?;
                        ranges.push((lo, u16::MAX));
                    } else {
                        set.insert(part.parse::<u16>().map_err(|e| {
                            Error::ConfigInvalid(format!("правило {raw:?}: порт {part:?}: {e}"))
                        })?);
                    }
                }
            }
            if set.is_empty() && ranges.is_empty() {
                return Err(Error::ConfigInvalid(format!(
                    "правило {raw:?}: не указан ни один порт"
                )));
            }
            Compiled::Port {
                set,
                ranges,
                policy,
            }
        }

        ProcessName | ProcessPath => Compiled::Process {
            set: parsed.args.iter().map(|a| a.to_string()).collect(),
            policy,
        },

        Uid => {
            let mut set = HashSet::new();
            for a in &parsed.args {
                set.insert(a.trim().parse::<u32>().map_err(|e| {
                    Error::ConfigInvalid(format!("правило {raw:?}: uid {a:?}: {e}"))
                })?);
            }
            Compiled::Uid { set, policy }
        }

        Network => {
            let v = parsed.arg(0).to_ascii_lowercase();
            let tcp = match v.as_str() {
                "tcp" => Some(true),
                "udp" => Some(false),
                other => {
                    return Err(Error::ConfigInvalid(format!(
                        "правило {raw:?}: network={other:?}, ожидалось tcp или udp"
                    )))
                }
            };
            Compiled::Network { tcp, policy }
        }
    })
}

// ───────────────────────────────── тесты ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn set(rules: &[&str], final_policy: &str) -> RuleSet {
        let owned: Vec<Rule> = rules.iter().map(|r| Rule::Plain(r.to_string())).collect();
        let f = crate::config::parse_policy(final_policy).unwrap();
        RuleSet::compile(&owned, &f, &GeoRegistry::empty()).unwrap()
    }

    fn flow(domain: Option<&str>, ip: Option<&str>, port: u16) -> Flow {
        Flow {
            dst_ip: ip.map(|s| s.parse().unwrap()),
            dst_port: port,
            src_port: 40000,
            is_tcp: true,
            uid: 1000,
            process: None,
            domain: domain.map(|s| s.to_string()),
            domain_confident: domain.is_some(),
        }
    }

    #[test]
    fn first_match_wins() {
        let rs = set(
            &[
                "DOMAIN,ads.com,REJECT",
                "DOMAIN-SUFFIX,example.com,Работа",
                "MATCH,DIRECT",
            ],
            "DIRECT",
        );
        let d = rs.decide(&flow(Some("ads.com"), None, 80));
        assert_eq!(d.0, Decision::Reject);
        let d = rs.decide(&flow(Some("a.example.com"), None, 80));
        assert_eq!(d.0, Decision::Proxy("Работа".into()));
        let d = rs.decide(&flow(Some("other.net"), None, 80));
        assert_eq!(d.0, Decision::Direct);
    }

    #[test]
    fn order_is_preserved_across_types() {
        // IP-правило стоит раньше доменного — должно выиграть именно оно.
        let rs = set(
            &["IP-CIDR,1.2.3.0/24,DIRECT", "DOMAIN,1.2.3.4,Работа"],
            "DIRECT",
        );
        let d = rs.decide(&flow(None, Some("1.2.3.4"), 80));
        assert_eq!(d.0, Decision::Direct);
    }

    #[test]
    fn fallback_used_when_nothing_matches() {
        let rs = set(&["DOMAIN,only-this.com,REJECT"], "Работа");
        let d = rs.decide(&flow(Some("unrelated.org"), None, 80));
        assert_eq!(d.0, Decision::Proxy("Работа".into()));
    }

    #[test]
    fn domain_suffix_does_not_match_lookalike() {
        let rs = set(
            &["DOMAIN-SUFFIX,example.com,REJECT", "MATCH,DIRECT"],
            "DIRECT",
        );
        assert_eq!(
            rs.decide(&flow(Some("example.com"), None, 80)).0,
            Decision::Reject
        );
        assert_eq!(
            rs.decide(&flow(Some("a.example.com"), None, 80)).0,
            Decision::Reject
        );
        assert_eq!(
            rs.decide(&flow(Some("notexample.com"), None, 80)).0,
            Decision::Direct
        );
        assert_eq!(
            rs.decide(&flow(Some("example.com.evil.net"), None, 80)).0,
            Decision::Direct
        );
    }

    #[test]
    fn ports_single_range_and_open_ended() {
        let rs = set(
            &[
                "DST-PORT,443,Работа",
                "DST-PORT,8000-9000,Работа2",
                "DST-PORT,1000+,Рабата3",
                "MATCH,DIRECT",
            ],
            "DIRECT",
        );
        assert_eq!(
            rs.decide(&flow(None, Some("9.9.9.9"), 443)).0,
            Decision::Proxy("Работа".into())
        );
        assert_eq!(
            rs.decide(&flow(None, Some("9.9.9.9"), 8080)).0,
            Decision::Proxy("Работа2".into())
        );
        assert_eq!(
            rs.decide(&flow(None, Some("9.9.9.9"), 8000)).0,
            Decision::Proxy("Работа2".into())
        );
        assert_eq!(
            rs.decide(&flow(None, Some("9.9.9.9"), 9000)).0,
            Decision::Proxy("Работа2".into())
        );
        // Портов ниже 1000, вне диапазона, — напрямую.
        assert_eq!(
            rs.decide(&flow(None, Some("9.9.9.9"), 500)).0,
            Decision::Direct
        );
        // Форма `1000+` ловит всё от 1000 и выше; 443 под неё не попадает,
        // потому что 443 ниже 1000.
        assert_eq!(
            rs.decide(&flow(None, Some("9.9.9.9"), 1000)).0,
            Decision::Proxy("Рабата3".into())
        );
        assert_eq!(
            rs.decide(&flow(None, Some("9.9.9.9"), 65535)).0,
            Decision::Proxy("Рабата3".into())
        );
    }

    #[test]
    fn cidr_matching_v4_and_v6() {
        let rs = set(
            &[
                "IP-CIDR,10.0.0.0/8,DIRECT",
                "IP-CIDR,2001:db8::/32,DIRECT",
                "MATCH,Работа",
            ],
            "Работа",
        );
        assert_eq!(
            rs.decide(&flow(None, Some("10.1.2.3"), 1)).0,
            Decision::Direct
        );
        assert_eq!(
            rs.decide(&flow(None, Some("2001:db8::1"), 1)).0,
            Decision::Direct
        );
        assert_eq!(
            rs.decide(&flow(None, Some("11.0.0.1"), 1)).0,
            Decision::Proxy("Работа".into())
        );
    }

    #[test]
    fn process_matches_basename_and_full_path() {
        let rs = set(&["PROCESS-NAME,firefox,Работа", "MATCH,DIRECT"], "DIRECT");
        let mut f = flow(None, Some("8.8.8.8"), 80);
        f.process = Some("/usr/lib/firefox/firefox".into());
        assert_eq!(rs.decide(&f).0, Decision::Proxy("Работа".into()));

        let mut f2 = flow(None, Some("8.8.8.8"), 80);
        f2.process = Some("/usr/bin/chromium".into());
        assert_eq!(rs.decide(&f2).0, Decision::Direct);
    }

    #[test]
    fn network_filter() {
        let rs = set(&["NETWORK,udp,DIRECT", "MATCH,Работа"], "Работа");
        let mut udp = flow(None, Some("1.1.1.1"), 53);
        udp.is_tcp = false;
        assert_eq!(rs.decide(&udp).0, Decision::Direct);
        assert_eq!(
            rs.decide(&flow(None, Some("1.1.1.1"), 443)).0,
            Decision::Proxy("Работа".into())
        );
    }

    #[test]
    fn regex_rule() {
        let rs = set(
            &[r"DOMAIN-REGEX,^ads[0-9]*\.,REJECT", "MATCH,DIRECT"],
            "DIRECT",
        );
        assert_eq!(
            rs.decide(&flow(Some("ads12.example.com"), None, 80)).0,
            Decision::Reject
        );
        assert_eq!(
            rs.decide(&flow(Some("myads.example.com"), None, 80)).0,
            Decision::Direct
        );
    }

    #[test]
    fn missing_domain_never_matches_domain_rules() {
        let rs = set(&["DOMAIN,example.com,REJECT", "MATCH,DIRECT"], "DIRECT");
        assert_eq!(
            rs.decide(&flow(None, Some("8.8.8.8"), 80)).0,
            Decision::Direct
        );
    }

    #[test]
    fn geo_rules_without_data_do_not_crash() {
        let rs = set(
            &[
                "GEOSITE,category-ads-all,REJECT",
                "GEOIP,cn,DIRECT",
                "MATCH,Работа",
            ],
            "Работа",
        );
        assert_eq!(rs.missing_geo().len(), 2);
        assert_eq!(
            rs.decide(&flow(Some("ads.example"), None, 80)).0,
            Decision::Proxy("Работа".into())
        );
    }

    #[test]
    fn cache_returns_same_decision() {
        let rs = set(&["DOMAIN,example.com,REJECT", "MATCH,DIRECT"], "DIRECT");
        let mut cache = std::collections::HashMap::new();
        let f = flow(Some("example.com"), None, 80);
        let a = rs.decide_cached(&f, &mut cache);
        let b = rs.decide_cached(&f, &mut cache);
        assert_eq!(a, b);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn compile_rejects_bad_regex_and_port() {
        let rules = vec![Rule::Plain("DOMAIN-REGEX,([unclosed,REJECT".into())];
        assert!(RuleSet::compile(&rules, &Policy::Direct, &GeoRegistry::empty()).is_err());

        let rules = vec![Rule::Plain("DST-PORT,99999,DIRECT".into())];
        assert!(RuleSet::compile(&rules, &Policy::Direct, &GeoRegistry::empty()).is_err());
    }
}

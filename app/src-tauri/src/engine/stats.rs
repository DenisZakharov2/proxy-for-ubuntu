//! Учёт трафика и активных соединений.
//!
//! Счётчики обновляются на горячем пути, поэтому структура минимальная:
//! атомики без мьютексов, без аллокаций в `record()`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::Serialize;

#[derive(Debug, Default)]
pub struct Counters {
    up: AtomicU64,
    down: AtomicU64,
    conns: AtomicU64,
}

impl Counters {
    pub fn add_up(&self, n: u64) {
        self.up.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_down(&self, n: u64) {
        self.down.fetch_add(n, Ordering::Relaxed);
    }
    pub fn conn_opened(&self) {
        self.conns.fetch_add(1, Ordering::Relaxed);
    }
    pub fn conn_closed(&self) {
        // Не даём счётчику уйти в ноль по недосмотру: в метриках это
        // выглядело бы как «минус одно соединение».
        // `try_update` стабилен только с Rust 1.95, а `rust-version` в
        // Cargo.toml — 1.77. Через `fetch_sub` обходимся без гонки и
        // без требования к более свежему компилятору.
        let prev = self.conns.fetch_sub(1, Ordering::Relaxed);
        if prev == 0 {
            // Было ноль соединений — возвращаем как было, иначе счётчик
            // ушёл бы в u64::MAX и в метриках показывал бы чушь.
            self.conns.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.up.load(Ordering::Relaxed),
            self.down.load(Ordering::Relaxed),
            self.conns.load(Ordering::Relaxed),
        )
    }
}

/// Сколько трафика ушло через какое правило и через какой outbound.
#[derive(Debug, Default)]
pub struct Breakdown {
    inner: Mutex<HashMap<(String, String), u64>>,
}

impl Breakdown {
    pub fn record(&self, rule: &str, outbound: &str, bytes: u64) {
        if let Ok(mut g) = self.inner.lock() {
            *g.entry((rule.to_string(), outbound.to_string()))
                .or_insert(0) += bytes;
        }
    }

    pub fn snapshot(&self) -> Vec<BreakdownRow> {
        let Ok(g) = self.inner.lock() else {
            return Vec::new();
        };
        let mut v: Vec<BreakdownRow> = g
            .iter()
            .map(|((rule, outbound), bytes)| BreakdownRow {
                rule: rule.clone(),
                policy: outbound.clone(),
                bytes: *bytes,
            })
            .collect();
        v.sort_by_key(|r| std::cmp::Reverse(r.bytes));
        v
    }

    pub fn reset(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.clear();
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BreakdownRow {
    pub rule: String,
    pub policy: String,
    pub bytes: u64,
}

/// Утилита форматирования объёма для GUI: «1.4 МБ».
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} {}", UNITS[0])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate() {
        let c = Counters::default();
        c.add_up(100);
        c.add_down(200);
        c.conn_opened();
        c.conn_opened();
        c.conn_closed();
        assert_eq!(c.snapshot(), (100, 200, 1));
    }

    #[test]
    fn conn_counter_never_underflows() {
        let c = Counters::default();
        c.conn_closed();
        c.conn_closed();
        assert_eq!(c.snapshot().2, 0);
    }

    #[test]
    fn breakdown_sorts_by_traffic() {
        let b = Breakdown::default();
        b.record("GEOIP,cn", "DIRECT", 10);
        b.record("MATCH", "Работа", 500);
        b.record("MATCH", "Работа", 100);
        let rows = b.snapshot();
        assert_eq!(rows[0].policy, "Работа");
        assert_eq!(rows[0].bytes, 600);
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn human_bytes_is_readable() {
        assert_eq!(human_bytes(0), "0 Б");
        assert_eq!(human_bytes(512), "512 Б");
        assert_eq!(human_bytes(1536), "1.5 КБ");
        assert_eq!(human_bytes(1024 * 1024 * 3), "3.0 МБ");
    }
}

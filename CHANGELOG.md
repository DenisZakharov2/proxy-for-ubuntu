# Changelog

Все значимые изменения в этом проекте описываются здесь.
Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версии следуют [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]

### Добавлено
- Пока ничего.

## [0.1.0] - 2026-10-06

Первый публичный релиз.

### Добавлено
- **Ядро маршрутизации.** Перехват системного TCP через `REDIRECT` и UDP
  через `TPROXY` с политической маршрутизацией по метке; маршруты системы
  не изменяются.
- **Rule engine в духе Clash.** Первое совпадение выигрывает. Типы:
  `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `DOMAIN-REGEX`, `IP-CIDR`,
  `GEOIP`, `GEOSITE`, `DST-PORT`, `SRC-PORT`, `PROCESS-NAME`, `PROCESS-PATH`,
  `UID`, `NETWORK`, `MATCH`. Действия: outbound, `DIRECT`, `REJECT`,
  `REJECT-DROP`, `HIJACK-DNS`.
- **Протоколы, написанные с нуля:** `direct`, `http` (CONNECT), `socks5`/`socks5h`,
  `shadowsocks` (AEAD: ChaCha20-Poly1305, AES-128/256-GCM), `trojan`.
  Дополнительно: `vless` (tcp/ws), `vmess` (AEAD, `alterId: 0`) — ⚠ не сверены
  с живым Xray-сервером.
- **SSH-туннель** через локальный SOCKS5 системного OpenSSH (`ssh -D`).
- **Собственный DNS.** Стратегии `fake-ip` (подмена на 198.18.0.0/16) и
  `redir-host`; кэш, fallback на DoH, синхронный перехват DNS.
- **Geo-наборы** — текстовые списки CIDR и доменов, обновление по URL с
  проверкой `sha256`.
- **Группы** типов `select`, `url-test`, `fallback`, `load-balance`, включая
  вложенность.
- **Применение с откатом.** Снапшот системного состояния → валидация →
  проверка живым соединением → применение → health-check → откат при ошибке.
- **Графическое приложение** на Tauri 2: тёмная и светлая темы, русский и
  английский, семь экранов, подтверждение опасных действий, диагностика.
- **`pfu-cli`** для headless-конфигурации: `status`, `connect`, `doctor`,
  `rules`, `proxies`, `metrics`, `geo`, `logs`, `apply`.
- **Пакет `.deb`** с `postinst`/`prerm`/`postrm`, systemd-юнитами и polkit.
- **Документация** на русском и английском: архитектура, схема конфигурации,
  IPC-контракт, протоколы, чек-лист тестирования.
- **117 модульных тестов** на движок, rule engine, протоколы и конфигурацию.

### Ограничения
- `vless` и `vmess` не проверены против живого сервера.
- `trojan` и `ssh` не пересылают UDP; для QUIC и игр нужен SOCKS5h или
  Shadowsocks.
- TUN-режим есть в конфигурации, но по умолчанию выключен: перехвата
  через nftables достаточно для TCP, UDP, DNS и QUIC.

# Материалы сессии 14 (29.10.2026): VMess через настоящий Xray

Стенд для проверки `vless`/`vmess` **нашим** кодом против живого Xray на этой
машине. CI делает то же самое в `.github/workflows/protocols.yml`, но локально
цикл — секунды вместо минут.

## Файлы

| Файл | Что |
|---|---|
| `xray.config.json` | конфиг Xray: inbound `vless` на 443, `vmess` (`alterId: 0`) на 444, `freedom` наружу |
| `pfu-config.yaml` | клиентский конфиг pfu: `VLESS-Test`, `VMESS-Test` (aes-128-gcm), `VMESS-Chacha` (chacha20-poly1305) |

## Запуск

```bash
cd "материалы сессии 14"
docker run -d --name pfu-xray-local \
  -p 1443:443 -p 1444:444 \
  -v "$PWD/xray.config.json:/etc/xray/config.json:ro" \
  docker.io/teddysun/xray@sha256:192de11069f271816eda94840d7940fd8dcdb8a7e5d67b5e1c68ab9a3afd9ff7

cd ../../app/src-tauri && cargo build --bin pfu-cli
for n in VLESS-Test VMESS-Test VMESS-Chacha; do
  ./target/debug/pfu-cli test-outbound --config "$OLDPWD/pfu-config.yaml" \
    --name "$n" --url http://example.com/ --timeout-ms 15000
done
docker rm -f pfu-xray-local
```

Ожидание (Xray 26.10.29, 29.10.2026): все три — `"ok": true`, `status: 200`,
923–930 байт, 120–1200 мс.

## Что было сломано и как проверялось

`vmess.rs` собирал заголовок «по мотивам» спецификации, и Xray в журнале
отвечал `invalid user > user do not exist`. Три расхождения:

1. `cmdKey` — это `MD5(uuid ‖ "c48619fe-8f02-49e0-b9e9-edf763e17e21")`
   (`protocol.NewID`), а не `MD5(uuid)`.
2. KDF — вложенный HMAC: у каждого уровня роль «хэша» играет предыдущий HMAC
   (`hmac.New` пишет ipad в него, `Sum` сбрасывает и дописывает opad). Проверен
   векторами из независимого переноса этого кода на Go.
3. Тело — кадры `len(2, BE) ‖ AEAD` со счётчиком в первых двух байтах IV;
   ответный заголовок (18 байт длины + тело) расшифровывается ключами
   `KDF16/KDF(responseBodyKey/IV, "AEAD Resp Header …")` и сверяется по
   маркеру. Читать его в `connect()` нельзя: сервер присылает заголовок только
   после данных → дедлок (симптом — «ответ не пришёл за 15 с»).

Диагностика по журналу Xray: `docker logs pfu-xray-local`.

## Замечания

- Порт 1443/1444, а не 443/444: на хосте 443 занят.
- Xray предупреждает, что VMess без forward secrecy устарел — для теста
  совместимости это не важно.
- Проверен **tcp без TLS**. TLS/ws-транспорты этим стендом не покрыты.

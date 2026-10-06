# Contributing to proxy-for-ubuntu

Спасибо, что хотите помочь. Ниже — как собрать проект, что нужно для PR и
как добавить новый прокси-протокол.

## Сборка из исходников

### Зависимости (Ubuntu 22.04 / 24.04)

```bash
sudo apt install build-essential pkg-config curl file patchelf \
     libssl-dev libgtk-3-dev libwebkit2gtk-4.1-dev \
     libayatana-appindicator3-dev librsvg2-dev
```

Rust — через [rustup](https://rustup.rs), стабильная ветка:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Проверка и сборка

```bash
cd app/src-tauri

cargo fmt --check          # форматирование обязательно
cargo clippy -- -D warnings
cargo test                 # 117 тестов, ~1 сек
cargo build --release --bins
```

### Пакет `.deb`

```bash
./scripts/build-deb.sh --output dist
sudo apt install ./dist/proxy-for-ubuntu_0.1.0_amd64.deb
```

Скрипт сам соберёт релизные бинарники, прогонит тесты и проверит результат
через `dpkg-deb --info`. Полезные флаги: `--skip-tests`, `--skip-build`,
`--version`, `--arch`.

### Запуск без установки

```bash
sudo app/src-tauri/target/debug/proxy-for-ubuntud --check   # проверка окружения
sudo app/src-tauri/target/debug/proxy-for-ubuntud --daemon  # демон
./app/src-tauri/target/debug/proxy-for-ubuntu               # GUI
```

GUI подключается к демону через `/run/proxy-for-ubuntu/ctl.sock`. Без запущенного
демона приложение покажет понятное сообщение, а не пустые экраны.

## Структура

```
app/ui/                  фронтенд GUI: index.html, style.css, app.js
app/src-tauri/src/
├── config.rs            схема конфигурации, валидация, подстановка ${VAR}
├── engine/
│   ├── rules.rs         компиляция и выполнение правил
│   ├── geo.rs           текстовые geo-наборы, обновление по URL
│   ├── router.rs        маршрутизация потока и relay
│   ├── nft.rs           генерация и применение правил nftables
│   ├── dns.rs           резолвер, fake-ip, кэш
│   ├── tls.rs           общая настройка TLS
│   ├── stats.rs         счётчики трафика
│   └── outbound/        по модулю на протокол
├── ipc.rs               сервер демона (обработчики методов)
├── ipc_client.rs        клиент сокета (им пользуются GUI и CLI)
├── supervisor.rs        apply, снапшоты и откат
└── paths.rs             системные пути, атомарная запись
docs/                    документация
packaging/               systemd, polkit, desktop, иконки, профили
debian/                  postinst, prerm, postrm, control
```

## Как добавить новый outbound-протокол

1. **Структура конфигурации** — добавьте вариант в `config::Outbound`
   (`app/src-tauri/src/config.rs`) вместе с собственной структурой полей и
   методом `validate()`. Не забудьте `test_url`.

2. **Реализация** — новый файл в `engine/outbound/<name>.rs`, реализация
   трейта `Outbound`:

   ```rust
   #[async_trait]
   impl Outbound for MyProto {
       fn name(&self) -> &str { &self.name }
       fn kind(&self) -> &'static str { "myproto" }
       fn supports_udp(&self) -> bool { self.udp }
       fn remote_dns(&self) -> bool { true }
       async fn connect(&self, req: &Request) -> Result<Box<dyn AsyncReadWrite>> { /* … */ }
       async fn open_udp(&self) -> Result<Arc<dyn UdpSession>> { /* … */ }
   }
   ```

   **Обязательно:**
   - таймаут на установление соединения — используйте
     `connect_proxy(server, Duration::from_secs(10))`, иначе Apply зависнет на
     мёртвом сервере вместо отката;
   - ошибки через `Error::protocol("myproto", "текст для пользователя")` —
     этот текст попадёт в GUI;
   - **тесты.** Поднимите локальный сервер на `127.0.0.1:0` и проверьте
     настоящий обмен байтами, а не только то, что конструктор не упал.

3. **Регистрация** — добавьте вариант в `Outbound::build`,
   `Outbound::kind`, `Outbound::supports_udp`, `Outbound::remote_dns` и
   `outbound::describe`. Последний печатает описание в лог — секреты там быть
   не должно.

4. **GUI** — добавьте поля в `PROTO_FIELDS` в `app/ui/app.js`. Если протокол
   не проверен на живом сервере, внесите его в `EXPERIMENTAL`: тогда он получит
   пометку ⚠ и предупреждение при добавлении.

5. **Документация** — `docs/PROTOCOLS.md` (спецификация, реализация, статус
   проверки, ограничения) и таблица в `README.md` / `README.en.md`.

6. **Пример** — `packaging/profiles/example.yaml`.

## Требования к PR

- `cargo fmt`, `cargo clippy -- -D warnings` и `cargo test` проходят.
- Новый код покрыт тестами, включая отрицательные случаи: битый ввод,
  неверный ключ, недоступный сервер.
- Тесты не висят: любой сетевой вызов оборачивайте в `tokio::time::timeout`.
  Тест, который может зависнуть, хуже отсутствующего теста.
- Ошибки, видимые пользователю, — на русском и английском (строки берутся из
  словаря в `app/ui/app.js`).
- Никаких «работает у меня» вместо теста. Если проверить нечем — так и
  напишите в PR и в документацию, пометив статус ⚠.
- Не добавляйте зависимость без обоснования. Особенно осторожно с крипто:
  своя реализация примитива — это уязвимость, а не фича.

## Стиль кода

- Комментарии объясняют **почему**, а не что. `// увеличиваем счётчик` над
  `i += 1` — шум. `// RwLockGuard не Send, поэтому отпускаем его до await` —
  польза.
- Русский язык в комментариях, строках ошибок и документации. Код —
  на английском.
- Никакой паники на пользовательских данных. `unwrap` допустим только там,
  где ошибка означает баг в коде, и с комментарием почему это невозможно.

## Сообщения об уязвимостях

Не открывайте публичный issue. См. [SECURITY.md](SECURITY.md).

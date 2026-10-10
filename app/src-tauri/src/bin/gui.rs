//! Графическое приложение proxy-for-ubuntu.
//!
//! GUI не имеет никаких системных прав: единственная его привилегированная
//! возможность — `ipc`-команда, которая пересылает запрос в сокет демона.
//! Всё, что меняет сеть, делает демон от root.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};

/// Запрос к демону в формате docs/IPC.md.
#[derive(Debug, Deserialize)]
struct IpcRequest {
    #[allow(dead_code)]
    id: Option<serde_json::Value>,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

/// Ответ демона, проксируемый фронтенду без изменений.
#[derive(Debug, Serialize)]
struct IpcResponse {
    id: Option<serde_json::Value>,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<serde_json::Value>,
    api: u32,
}

/// Переменные окружения, которые выставляются ДО создания окна.
///
/// WebKitGTK на LXQt/Xfce с оконным менеджером Openbox и композитором picom
/// штатно не рисует содержимое webview: окно появляется, но остаётся
/// пустым и прозрачным. Причина — DMABUF-путь, который требует поддержки
/// со стороны композитора, которой у picom в связке с Openbox нет.
///
/// Переменные обязаны быть выставлены до инициализации GTK/WebKit, то
/// есть до `tauri::Builder::run`, иначе они не подействуют.
fn prepare_webkit_env() {
    for (var, value) in [
        // Наш интерфейс — набор форм и таблиц. Программный рендеринг
        // для него более чем достаточен, а прозрачность бага убирает.
        ("WEBKIT_DISABLE_DMABUF_RENDERER", "1"),
        // Композитинг WebKit в окне без поддержки оверлеев даёт артефакты
        // и, на части конфигураций, те же пустые окна.
        ("WEBKIT_DISABLE_COMPOSITING_MODE", "1"),
    ] {
        if std::env::var_os(var).is_none() {
            // SAFETY: дочерних потоков ещё нет, мы в начале main().
            unsafe { std::env::set_var(var, value) };
        }
    }
}

fn main() {
    // Служебные подкоманды разбираем до GTK: на машине с проблемами
    // рендеринга именно они дают пользователю хоть какой-то вывод.
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => {
            println!(
                "proxy-for-ubuntu {} (IPC api {})",
                pfu::VERSION,
                pfu::API_VERSION
            );
            return;
        }
        Some("--diagnose") => {
            print_diagnose();
            return;
        }
        _ => {}
    }

    prepare_webkit_env();

    // Паника здесь означала бы стек-трейс вместо внятного объяснения.
    // На машине без дисплея или со сломанным WebKitGTK пользователь должен
    // видеть, что делать, а не стек Rust.
    if let Err(e) = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![ipc])
        .run(tauri::generate_context!())
    {
        eprintln!("proxy-for-ubuntu: не удалось открыть окно: {e}");
        eprintln!();
        eprintln!("Частые причины:");
        eprintln!("  • нет дисплея — проверьте DISPLAY или WAYLAND_DISPLAY");
        eprintln!("  • сбой WebKitGTK на LXQt/Xfce:");
        eprintln!("       LIBGL_ALWAYS_SOFTWARE=1 proxy-for-ubuntu");
        eprintln!("  • подробности: proxy-for-ubuntu --diagnose");
        std::process::exit(1);
    }
}

/// Единственная команда фронтенда. Формат запроса и все коды ошибок заданы
/// в docs/IPC.md и дублируются в протоколе демона.
#[tauri::command]
async fn ipc(request: IpcRequest) -> IpcResponse {
    match pfu::ipc_client::call(&request.method, request.params).await {
        Ok(result) => IpcResponse {
            id: request.id,
            ok: true,
            result: Some(result),
            error: None,
            api: pfu::API_VERSION,
        },
        Err(e) => IpcResponse {
            id: request.id,
            ok: false,
            result: None,
            error: Some(serde_json::json!({
                "code": e.code(),
                "message": e.to_string(),
                "hint": e.hint(),
                "stage": e.stage(),
            })),
            api: pfu::API_VERSION,
        },
    }
}

/// Печатает то, что поможет понять, почему окно пустое или не открывается.
///
/// Собирается специально «на глаз», без всякой красоты: пользователь с
/// пустым окном должен иметь возможность получить диагностику командой
/// в терминале.
fn print_diagnose() {
    println!(
        "proxy-for-ubuntu {} — диагностика окружения GUI",
        pfu::VERSION
    );
    println!();

    println!("WebKit:");
    for var in [
        "WEBKIT_DISABLE_DMABUF_RENDERER",
        "WEBKIT_DISABLE_COMPOSITING_MODE",
        "WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS",
    ] {
        match std::env::var(var) {
            Ok(v) => println!("  {var}={v}"),
            Err(_) => println!("  {var} — не задан (подставляется автоматически)"),
        }
    }
    println!(
        "  GTK_IM_MODULE={}",
        std::env::var("GTK_IM_MODULE").unwrap_or_default()
    );
    println!();

    println!("Графическая сессия:");
    for var in [
        "XDG_SESSION_TYPE",
        "XDG_CURRENT_DESKTOP",
        "DESKTOP_SESSION",
        "WAYLAND_DISPLAY",
        "DISPLAY",
    ] {
        println!(
            "  {var}={}",
            std::env::var(var).unwrap_or_else(|_| "—".into())
        );
    }
    println!();

    println!("Сокет демона:");
    let sock = pfu::paths::ctl_socket();
    println!("  путь: {}", sock.display());
    match std::os::unix::net::UnixStream::connect(&sock) {
        Ok(_) => println!("  статус: отвечает"),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            println!("  статус: Permission denied — пользователь не в группе proxy-for-ubuntu");
            println!(
                "  исправить: sudo usermod -aG proxy-for-ubuntu $USER && newgrp proxy-for-ubuntu"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("  статус: демон не запущен");
            println!("  исправить: sudo systemctl start proxy-for-ubuntud");
        }
        Err(e) => println!("  статус: {e}"),
    }
    println!();

    println!("Если окно открывается пустым:");
    println!("  1. WEBKIT_DISABLE_DMABUF_RENDERER=1 уже выставляется автоматически.");
    println!("  2. Если не помогло — попробуйте программный рендеринг OpenGL:");
    println!("       LIBGL_ALWAYS_SOFTWARE=1 proxy-for-ubuntu");
    println!("  3. Отправьте вывод этой команды в issue, приложив сведения об окружении.");
}

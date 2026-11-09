// Serrier desktop (Tauri v2) — tunt skal. Startar Python-backenden som en managed SIDECAR
// på en fast loopback-port vid start, och dödar den vid avslut. Fönstret visar den statiskt
// exporterade Next.js-dashboarden, som pratar med sidecaren över loopback (token + Host-
// allowlist, se docs/design/0004 §4).
//
// Scaffold — kompileras med Rust-toolchain (se desktop/README). Ej byggt/verifierat i den
// headless dev-miljö där det skrevs; API-detaljer kan behöva justeras mot exakt plugin-version.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use tauri::Manager;
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::ShellExt;

// Håll barn-processen så vi kan döda den rent vid avslut.
struct Sidecar(Mutex<Option<CommandChild>>);

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(Sidecar(Mutex::new(None)))
        .setup(|app| {
            // Starta backend-sidecaren (binaries/serrier-backend-<target-triple>).
            let (_rx, child) = app
                .shell()
                .sidecar("serrier-backend")
                .expect("sidecar 'serrier-backend' saknas — bygg den först (se desktop/README)")
                .spawn()
                .expect("kunde inte starta backend-sidecaren");
            *app.state::<Sidecar>().0.lock().unwrap() = Some(child);
            Ok(())
        })
        .on_window_event(|window, event| {
            // Döda sidecaren när fönstret stängs — ingen kvarlämnad bakgrundsprocess.
            if let tauri::WindowEvent::Destroyed = event {
                if let Some(child) = window.app_handle().state::<Sidecar>().0.lock().unwrap().take()
                {
                    let _ = child.kill();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("fel vid körning av Serrier desktop");
}

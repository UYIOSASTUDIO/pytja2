use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing_appender::non_blocking::WorkerGuard;
use std::path::Path;

/// Initialisiert das Logging-System.
/// Gibt einen "WorkerGuard" zurück. WICHTIG: Dieser darf nicht gedroppt werden,
/// solange das Programm läuft, sonst stoppt das Logging.
pub fn init_telemetry(log_dir: &str, file_name: &str) -> WorkerGuard {
    // 1. Erstelle das Verzeichnis für Logs, falls nicht existent
    if !Path::new(log_dir).exists() {
        let _ = std::fs::create_dir_all(log_dir);
    }

    // 2. Rolling File Appender (Täglich neue Datei)
    let file_appender = tracing_appender::rolling::daily(log_dir, file_name);

    // 3. Non-Blocking Writer
    // Das ist der Performance-Trick: Das Schreiben passiert in einem separaten Thread.
    // Deine App wartet NIEMALS auf die Festplatte.
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // 4. Konfiguration des Formats (Wir nehmen JSON für Maschinenlesbarkeit)
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking)
        .json() // Strukturiertes JSON
        .with_file(true)
        .with_line_number(true)
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false);

    // 5. Registrieren
    // Wir filtern auf "INFO" Level. Alles darunter (DEBUG, TRACE) wird ignoriert,
    // es sei denn, wir ändern die Config.
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info,pytja_core=debug")) // Core debuggen wir genauer
        .with(file_layer)
        .init();

    guard
}
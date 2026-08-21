// `tauri_build::build()` liest `src-tauri/tauri.conf.json` und erzeugt daraus
// die ACL- und Kontextbeiwerke, die `tauri::generate_context!` in `src/lib.rs`
// einliest. Beides entsteht in Task 15; der Stumpf von Task 13 ist damit
// abgeloest.
fn main() {
    tauri_build::build();
}

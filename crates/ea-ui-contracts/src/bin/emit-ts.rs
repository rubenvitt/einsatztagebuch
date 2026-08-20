//! Der EINZIGE Schreiber von `apps/desktop/src/bridge/generated-contracts.ts`.
//!
//! Er druckt nichts. Ein Emitter, der etwas druckt, verleitet dazu, seine
//! Ausgabe zu lesen statt seine Datei zu committen — und die Driftschranke
//! prueft die Datei.
//!
//! Das Ziel wird gegen `CARGO_MANIFEST_DIR` aufgeloest und nicht gegen das
//! aktuelle Arbeitsverzeichnis: der Pfad ist damit derselbe, egal aus welchem
//! Unterverzeichnis des Arbeitsbereichs `cargo run` startet.

use std::{fs, path::PathBuf};

fn main() {
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../apps/desktop/src/bridge/generated-contracts.ts");
    let directory = target
        .parent()
        .expect("the generated contracts path must have a parent directory");
    fs::create_dir_all(directory).expect("the bridge directory must be creatable");
    fs::write(&target, ea_ui_contracts::emit_typescript())
        .expect("the generated contracts file must be writable");
}

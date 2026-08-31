//! Der EINZIGE Schreiber der ZWEI generierten Kontraktdateien.
//!
//! Er druckt nichts. Ein Emitter, der etwas druckt, verleitet dazu, seine
//! Ausgabe zu lesen statt seine Datei zu committen — und die Driftschranke
//! prueft die Datei.
//!
//! Die Ziele werden gegen `CARGO_MANIFEST_DIR` aufgeloest und nicht gegen das
//! aktuelle Arbeitsverzeichnis: der Pfad ist damit derselbe, egal aus welchem
//! Unterverzeichnis des Arbeitsbereichs `cargo run` startet.
//!
//! ZWEI Ziele in EINEM Lauf, und das ist keine Bequemlichkeit: zwei Kommandos
//! liessen die eine Datei aktuell und die andere veraltet zurueck, und genau
//! diese Haelfte wuerde niemand bemerken.

use std::{fs, path::PathBuf};

fn write_contracts(relative_target: &str, contents: &str) {
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_target);
    let directory = target
        .parent()
        .expect("the generated contracts path must have a parent directory");
    fs::create_dir_all(directory).expect("the bridge directory must be creatable");
    fs::write(&target, contents).expect("the generated contracts file must be writable");
}

fn main() {
    write_contracts(
        "../../apps/desktop/src/bridge/generated-contracts.ts",
        &ea_ui_contracts::emit_typescript(),
    );
    write_contracts(
        "../../apps/web/src/bridge/generated-contracts.ts",
        &ea_ui_contracts::emit_reader_typescript(),
    );
}

//! Wiederherstellungswerkzeug des Einsatzarchivs.
//!
//! Skelett. Die Argumentgrammatik der fuenf Kommandos verify, list, decrypt,
//! report und export ist noch nicht implementiert, deshalb beendet sich jeder
//! Lauf mit `Unsupported` (21). Ausdruecklich NICHT mit `Usage` (2): der Code 2
//! gehoert der Grammatikpruefung, und ein Skelett, das ihn schon liefert,
//! machte deren erstes Fehlschlagen wertlos.

fn main() -> std::process::ExitCode {
    eprintln!(
        "einsatzarchiv: the command grammar is not implemented yet; \
         no archive was read and nothing was written"
    );
    std::process::ExitCode::from(21)
}

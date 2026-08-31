//! Native Gegenprobe. Laeuft dieselben vier Elemente auf dem Host-Target, damit
//! ein Fehlschlag unter wasm32 eindeutig ein wasm-Problem ist und keine
//! Vektor- oder Erwartungswertfrage.
//!
//! Beendet sich mit 1, sobald ein Element scheitert.

fn main() {
    let report = ea_wasm_runtime_proof::runtime_proof_json();
    println!("{report}");
    if report.contains("\"ok\":true") {
        eprintln!("native baseline: OK");
    } else {
        eprintln!("native baseline: FAILED");
        std::process::exit(1);
    }
}

//! CLI-Grenze für den nativen Operator-Lebenszyklus.
//!
//! `ea-admin::OperatorBindingService` führt die Zeremonie über verifizierte
//! Trust-, Konto-, Präsenz-, Schlüssel- und Audit-Ports. Das ausgelieferte CLI
//! besitzt noch keine native Host-Komposition für diese Ports. Ohne sie kann
//! es weder eine tatsächliche OS-Identität noch einen Login auditieren. Dieser
//! Pfad weist den Aufruf vor jeder Datei- oder Schlüsseländerung zurück.

use ea_recovery::ExitCode;

use crate::{args::OperatorAction, output};

pub fn run(action: OperatorAction) -> ExitCode {
    match action {
        OperatorAction::Provision | OperatorAction::VerifySession | OperatorAction::Revoke => {
            output::print_operator_provider_refusal();
            ExitCode::Unsupported
        }
    }
}

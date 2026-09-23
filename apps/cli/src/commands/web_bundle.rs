//! Die minimale Root-Zeremonie der Bundle-Familie (U4):
//! `organization web-bundle-release|web-bundle-revoke`.
//!
//! Die Fachlogik wohnt in `ea_admin::web_bundle_release`; hier wird geladen,
//! aufgerufen, gedruckt und ein Exitcode zugeordnet. Der Bericht trägt nur
//! Objekthashes und die Fähigkeit der Fassung. Eine JSON-Form gibt es nicht.
//!
//! Der Einstieg liegt hier und nicht in `organization.rs`: jene Datei wird von
//! einem zweiten Testziel per `#[path]` eingebunden, in dem dieses Modul nicht
//! existiert.
use crate::{args::Format, args::Invocation, output};
use ea_admin::{
    operator_runtime::{OperatorRuntime, OperatorRuntimeConfig, OperatorRuntimeError},
    web_bundle_release::{PublishedWebBundleObject, WebBundleRequest, publish_web_bundle_object},
};
use ea_recovery::{ExitCode, ReaderKeyEscrowError};
use ea_types::{RegistryVersion, UnixMillis};
use std::path::Path;

/// Wie eine Laufzeit geöffnet wird. Der ausgelieferte Einstieg wählt immer den
/// installierten Wirt; nur das getrennte Testbinär reicht einen Fixture-Öffner.
pub type RuntimeOpener<'a> = &'a dyn Fn(
    OperatorRuntimeConfig,
    &Path,
    UnixMillis,
) -> Result<OperatorRuntime, OperatorRuntimeError>;

fn installed(
    config: OperatorRuntimeConfig,
    anchor: &Path,
    now: UnixMillis,
) -> Result<OperatorRuntime, OperatorRuntimeError> {
    OperatorRuntime::open(config, anchor, now, false)
}

pub fn run_release(
    invocation: &Invocation,
    config: &Path,
    bundle: &Path,
    bundle_version: &str,
    effective_from: Option<RegistryVersion>,
    now: UnixMillis,
) -> ExitCode {
    run_release_with_runtime_opener(
        invocation,
        config,
        bundle,
        bundle_version,
        effective_from,
        now,
        &installed,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn run_release_with_runtime_opener(
    invocation: &Invocation,
    config: &Path,
    bundle: &Path,
    bundle_version: &str,
    effective_from: Option<RegistryVersion>,
    now: UnixMillis,
    opener: RuntimeOpener<'_>,
) -> ExitCode {
    match WebBundleRequest::release_of_bundle_file(
        bundle,
        bundle_version.to_owned(),
        effective_from,
    ) {
        Ok(request) => run(invocation, config, now, opener, request),
        Err(error) => failure(error),
    }
}

pub fn run_revoke(
    invocation: &Invocation,
    config: &Path,
    release: &Path,
    effective_from: Option<RegistryVersion>,
    now: UnixMillis,
) -> ExitCode {
    run_revoke_with_runtime_opener(invocation, config, release, effective_from, now, &installed)
}

pub fn run_revoke_with_runtime_opener(
    invocation: &Invocation,
    config: &Path,
    release: &Path,
    effective_from: Option<RegistryVersion>,
    now: UnixMillis,
    opener: RuntimeOpener<'_>,
) -> ExitCode {
    // Genannt wird die Freigabe über ihre exakten Bytes; der Objekthash ist
    // derselbe, den der Katalog führt.
    match WebBundleRequest::revocation_of_release_file(release, effective_from) {
        Ok(request) => run(invocation, config, now, opener, request),
        Err(error) => failure(error),
    }
}

fn run(
    invocation: &Invocation,
    config: &Path,
    now: UnixMillis,
    opener: RuntimeOpener<'_>,
    request: WebBundleRequest,
) -> ExitCode {
    if invocation.format == Format::Json {
        output::print_web_bundle_json_refusal();
        return ExitCode::Unsupported;
    }
    let config = match OperatorRuntimeConfig::load(config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{}", error.code());
            return error.exit_code();
        }
    };
    let runtime = match opener(config, &invocation.anchor, now) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("{}", error.code());
            return error.exit_code();
        }
    };
    match publish_web_bundle_object(&runtime, request) {
        Ok(published) => {
            report(&published);
            ExitCode::Success
        }
        Err(error) => failure(error),
    }
}

fn report(published: &PublishedWebBundleObject) {
    let (action, capable) = match published.carries_reader_key_escrow {
        Some(capable) => ("released", Some(capable)),
        None => ("revoked", None),
    };
    output::print_web_bundle_report(action, published.object_hash.as_bytes(), capable);
}

fn failure(error: ReaderKeyEscrowError) -> ExitCode {
    eprintln!("{}", error.code());
    error.exit_code()
}

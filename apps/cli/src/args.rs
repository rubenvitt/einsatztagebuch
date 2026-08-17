//! Die geschlossene Aufrufgrammatik, von Hand geparst.
//!
//! # Warum von Hand und nicht mit `clap`
//!
//! Die Grammatik ist mit fuenf Kommandos, vier wertnehmenden Schaltern und
//! einem Flag abgeschlossen und klein. Das Repo ist dependency-diszipliniert:
//! jede externe Kiste traegt eine begruendete Zeile in
//! `docs/adr/0001-toolchain-and-cryptography-dependencies.md`. Eine
//! Argumentbibliothek in den Graphen eines WIEDERHERSTELLUNGSWERKZEUGS zu
//! ziehen, das Jahre nach seiner Uebersetzung noch bauen und laufen soll, ist
//! der teurere Weg — nicht der billigere.
//!
//! # [`parse`] ist REIN
//!
//! Sie nimmt einen Iterator und ruft nirgends [`std::env::args_os`] selbst.
//! Nur so ist jeder Aufruffehler ohne Prozessstart messbar; der Prozessstart
//! misst danach den Exitcode und nicht mehr die Grammatik.
//!
//! # Zwei festgeschriebene Konventionen
//!
//! - **Werte stehen als EIGENES Argument hinter dem Schalter.** `--format=json`
//!   ist ein unbekannter Schalter und damit [`UsageError::UnknownSwitch`]. Eine
//!   Form, die beides stillschweigend annimmt, hat doppelt so viele Pfade und
//!   halb so viele Tests.
//! - **Ein Argument, dessen erstes Byte `-` ist, ist ein SCHALTER.** Auch als
//!   Wert eines Schalters: `--output --format` meldet den fehlenden Wert von
//!   `--output`, statt `--format` als Zielpfad zu verschlucken. Ein Zielpfad,
//!   der wirklich mit `-` beginnt, wird als `./-name` uebergeben.
//!
//! # Nicht-UTF-8
//!
//! SCHALTERNAMEN und Kommandonamen muessen UTF-8 sein — sie werden gegen feste
//! Zeichenketten verglichen, und was sich damit nicht vergleichen laesst, ist
//! keiner von ihnen. PFADWERTE gehen dagegen unbesehen als [`OsString`] in
//! [`PathBuf`]: auf darwin und Linux ist ein Pfad eine Bytefolge, und ein
//! Wiederherstellungswerkzeug, das einen Bestand wegen der Kodierung seines
//! Verzeichnisnamens nicht oeffnet, versagt genau dann, wenn es gebraucht wird.

use std::{ffi::OsString, fmt, path::PathBuf};

/// `--trust-anchor <file>`, PFLICHT bei allen fuenf Kommandos.
pub const TRUST_ANCHOR_SWITCH: &str = "--trust-anchor";
/// `--format text|json`, Vorgabe `text`.
pub const FORMAT_SWITCH: &str = "--format";
/// `--output <target>`, bei `decrypt`, `report` und `export`.
pub const OUTPUT_SWITCH: &str = "--output";
/// `--key <key-source>`, nur bei `decrypt`.
pub const KEY_SWITCH: &str = "--key";
/// `--include-runtime-metadata`, nur bei `report`.
pub const INCLUDE_RUNTIME_METADATA_SWITCH: &str = "--include-runtime-metadata";

/// Die Ausgabeform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    /// Zeilenweise stabile Schluessel-Wert-Paare.
    Text,
    /// Das Berichtsdokument `ea.verification-report/v1`.
    Json,
}

/// Das gewaehlte Kommando samt seinen Pfaden.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    /// Bestand pruefen und berichten.
    Verify {
        /// Wurzel des Bestands.
        archive: PathBuf,
    },
    /// Bestand pruefen und seine Objektergebnisse auflisten.
    List {
        /// Wurzel des Bestands.
        archive: PathBuf,
    },
    /// Bestand pruefen und danach Klartext in ein neues Ziel schreiben.
    Decrypt {
        /// Wurzel des Bestands.
        archive: PathBuf,
        /// Herkunft des Empfaengerschluessels.
        key: PathBuf,
        /// Neues oder leeres Zielverzeichnis.
        output: PathBuf,
    },
    /// Bestand pruefen und den Bericht kanonisch in eine Datei schreiben.
    Report {
        /// Wurzel des Bestands.
        archive: PathBuf,
        /// Zieldatei des Berichts.
        output: PathBuf,
    },
    /// Bestand pruefen und ihn VERSCHLUESSELT vollstaendig kopieren.
    Export {
        /// Wurzel des Bestands oder Serverquelle.
        source: PathBuf,
        /// Neues oder leeres Zielverzeichnis.
        output: PathBuf,
    },
}

/// Ein vollstaendig geparster Aufruf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    /// Der Trust Anchor. Kommt von aussen und NIE aus dem Bestand.
    pub anchor: PathBuf,
    /// Die Ausgabeform.
    pub format: Format,
    /// Der EINZIGE Weg zu nichtdeterministischen Berichtsfeldern.
    pub include_runtime_metadata: bool,
    /// Das gewaehlte Kommando.
    pub command: Command,
}

/// Ein Aufruffehler. Endet ausnahmslos mit [`ea_recovery::ExitCode::Usage`].
///
/// Jede Auspraegung nennt in ihrer Anzeige den fehlenden oder falschen Namen
/// WOERTLICH. Ein Test darf darauf assertieren; ein Aufrufer soll daran
/// erkennen, was er zu aendern hat.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UsageError {
    /// Es wurde ueberhaupt kein Argument uebergeben.
    ///
    /// Der EINZIGE Fall, dessen Ausgabe nach stdout geht: eine Grammatik, nach
    /// der jemand ohne Argumente fragt, ist eine Nutzausgabe und keine
    /// Fehlermeldung.
    NoArguments,
    /// Ein Argument beginnt mit `-` und ist keiner der fuenf Schalter.
    UnknownSwitch(String),
    /// Ein wertnehmender Schalter steht ohne Wert da.
    MissingValue(&'static str),
    /// Derselbe Schalter wurde mehr als einmal angegeben.
    DuplicateSwitch(&'static str),
    /// `--format` traegt etwas anderes als `text` oder `json`.
    UnknownFormat(String),
    /// Das erste Positionsargument ist keines der fuenf Kommandos.
    UnknownCommand(String),
    /// Es wurde ein Schalter, aber kein Kommando angegeben.
    MissingCommand,
    /// `--trust-anchor` fehlt.
    MissingTrustAnchor,
    /// Das Kommando braucht ein Positionsargument, bekam aber keines.
    MissingPositional(&'static str),
    /// Das Kommando nimmt genau ein Positionsargument, bekam aber mehrere.
    SurplusPositional(&'static str),
    /// Das Kommando verlangt einen Schalter, der fehlt.
    MissingSwitch {
        /// Der fehlende Schalter.
        switch: &'static str,
        /// Das Kommando, das ihn verlangt.
        command: &'static str,
    },
    /// Der Schalter existiert, gehoert aber nicht zu diesem Kommando.
    SwitchNotAllowed {
        /// Der abgelehnte Schalter.
        switch: &'static str,
        /// Das Kommando, das ihn nicht kennt.
        command: &'static str,
    },
}

impl fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoArguments => formatter.write_str("no command was given"),
            Self::UnknownSwitch(switch) => write!(formatter, "unknown switch {switch}"),
            Self::MissingValue(switch) => write!(formatter, "{switch} requires a value"),
            Self::DuplicateSwitch(switch) => {
                write!(formatter, "{switch} was given more than once")
            }
            Self::UnknownFormat(value) => write!(
                formatter,
                "{FORMAT_SWITCH} accepts only text or json, not {value}"
            ),
            Self::UnknownCommand(command) => write!(
                formatter,
                "unknown command {command}; expected verify, list, decrypt, report or export"
            ),
            Self::MissingCommand => formatter.write_str(
                "no command was given; expected verify, list, decrypt, report or export",
            ),
            Self::MissingTrustAnchor => write!(
                formatter,
                "{TRUST_ANCHOR_SWITCH} is required for every command"
            ),
            Self::MissingPositional(command) => write!(
                formatter,
                "{command} requires exactly one positional argument, none was given"
            ),
            Self::SurplusPositional(command) => write!(
                formatter,
                "{command} takes exactly one positional argument, more were given"
            ),
            Self::MissingSwitch { switch, command } => {
                write!(formatter, "{command} requires {switch}")
            }
            Self::SwitchNotAllowed { switch, command } => {
                write!(formatter, "{switch} is not allowed for {command}")
            }
        }
    }
}

impl std::error::Error for UsageError {}

/// Welches der fuenf Kommandos gemeint ist.
///
/// Eine eigene Aufzaehlung statt einer Zeichenkette, damit die Auswertung unten
/// VOLLSTAENDIG ist und kein `unreachable!()` braucht. Ein `unreachable!()`
/// waere eine Behauptung; eine Aufzaehlung ist ein Beweis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandKind {
    Verify,
    List,
    Decrypt,
    Report,
    Export,
}

impl CommandKind {
    /// Der Name, wie er in der Eingabezeile steht und in Meldungen erscheint.
    const fn name(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::List => "list",
            Self::Decrypt => "decrypt",
            Self::Report => "report",
            Self::Export => "export",
        }
    }

    /// Erkennt ein Kommando. Die Zuordnung ist exakt und ohne Abkuerzungen.
    fn from_token(token: &str) -> Option<Self> {
        match token {
            "verify" => Some(Self::Verify),
            "list" => Some(Self::List),
            "decrypt" => Some(Self::Decrypt),
            "report" => Some(Self::Report),
            "export" => Some(Self::Export),
            _ => None,
        }
    }
}

/// Wahr, wenn das Argument als Schalter zu lesen ist.
///
/// Prueft das erste BYTE und nicht das erste Zeichen: ein nicht-UTF-8-Argument
/// hat kein erstes Zeichen, aber sehr wohl ein erstes Byte, und ob es ein
/// Schalter sein WILL, entscheidet sich vor jeder Kodierungsfrage.
fn looks_like_switch(argument: &OsString) -> bool {
    argument.as_encoded_bytes().first() == Some(&b'-')
}

/// Liest den Wert eines wertnehmenden Schalters in `slot`.
///
/// Erkennt dabei die doppelte Angabe: der Slot ist die einzige Stelle, an der
/// „schon gesetzt" ueberhaupt sichtbar ist.
fn take_path_value(
    slot: &mut Option<PathBuf>,
    switch: &'static str,
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<(), UsageError> {
    if slot.is_some() {
        return Err(UsageError::DuplicateSwitch(switch));
    }
    let value = arguments.next().ok_or(UsageError::MissingValue(switch))?;
    if looks_like_switch(&value) {
        return Err(UsageError::MissingValue(switch));
    }
    *slot = Some(PathBuf::from(value));
    Ok(())
}

/// Parst die Argumente OHNE den Programmnamen.
///
/// Der Aufrufer uebergibt `std::env::args_os().skip(1)`. Das `skip` steht dort
/// und nicht hier, damit jeder Unittest die reine Argumentfolge schreibt und
/// nicht ein Fuellelement mitschleppt, das niemanden interessiert.
///
/// # Pruefreihenfolge
///
/// Fest und dokumentiert, damit bei mehreren Verstoessen immer dieselbe Meldung
/// erscheint:
///
/// 1. Fehler waehrend des Durchlaufs, in der Reihenfolge der Argumente:
///    unbekannter Schalter, fehlender Wert, doppelter Schalter, unbekannter
///    `--format`-Wert, unbekanntes Kommando.
/// 2. Gar kein Argument, danach: kein Kommando.
/// 3. Fehlender `--trust-anchor`.
/// 4. Schalter, die dieses Kommando nicht kennt.
/// 5. Anzahl der Positionsargumente.
/// 6. Schalter, die dieses Kommando verlangt.
///
/// # Errors
///
/// [`UsageError`] in jeder oben genannten Lage. Ein Aufruffehler ist
/// ausdruecklich KEIN Befund ueber einen Bestand: hier wurde noch kein Byte
/// gelesen.
pub fn parse(arguments: impl Iterator<Item = OsString>) -> Result<Invocation, UsageError> {
    let mut arguments = arguments;

    let mut anchor: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut key: Option<PathBuf> = None;
    let mut format: Option<Format> = None;
    let mut include_runtime_metadata: Option<bool> = None;
    let mut command_kind: Option<CommandKind> = None;
    let mut positionals: Vec<PathBuf> = Vec::new();
    let mut saw_any_argument = false;

    while let Some(argument) = arguments.next() {
        saw_any_argument = true;

        if looks_like_switch(&argument) {
            let Some(switch) = argument.to_str() else {
                // Kein Schaltername des Repertoires ist nicht-UTF-8, also ist
                // dieser hier keiner. Die verlustbehaftete Wiedergabe ist die
                // Eingabe des Aufrufers und nichts aus einem Bestand.
                return Err(UsageError::UnknownSwitch(
                    argument.to_string_lossy().into_owned(),
                ));
            };
            match switch {
                TRUST_ANCHOR_SWITCH => {
                    take_path_value(&mut anchor, TRUST_ANCHOR_SWITCH, &mut arguments)?;
                }
                OUTPUT_SWITCH => take_path_value(&mut output, OUTPUT_SWITCH, &mut arguments)?,
                KEY_SWITCH => take_path_value(&mut key, KEY_SWITCH, &mut arguments)?,
                FORMAT_SWITCH => {
                    if format.is_some() {
                        return Err(UsageError::DuplicateSwitch(FORMAT_SWITCH));
                    }
                    let value = arguments
                        .next()
                        .ok_or(UsageError::MissingValue(FORMAT_SWITCH))?;
                    if looks_like_switch(&value) {
                        return Err(UsageError::MissingValue(FORMAT_SWITCH));
                    }
                    format = Some(match value.to_str() {
                        Some("text") => Format::Text,
                        Some("json") => Format::Json,
                        _ => {
                            return Err(UsageError::UnknownFormat(
                                value.to_string_lossy().into_owned(),
                            ));
                        }
                    });
                }
                INCLUDE_RUNTIME_METADATA_SWITCH => {
                    if include_runtime_metadata.is_some() {
                        return Err(UsageError::DuplicateSwitch(INCLUDE_RUNTIME_METADATA_SWITCH));
                    }
                    include_runtime_metadata = Some(true);
                }
                _ => return Err(UsageError::UnknownSwitch(switch.to_owned())),
            }
        } else if command_kind.is_none() {
            let kind = argument
                .to_str()
                .and_then(CommandKind::from_token)
                .ok_or_else(|| {
                    UsageError::UnknownCommand(argument.to_string_lossy().into_owned())
                })?;
            command_kind = Some(kind);
        } else {
            positionals.push(PathBuf::from(argument));
        }
    }

    // 2 — gar nichts, danach: nur Schalter.
    if !saw_any_argument {
        return Err(UsageError::NoArguments);
    }
    let command_kind = command_kind.ok_or(UsageError::MissingCommand)?;
    let command_name = command_kind.name();

    // 3 — der Anker. `design.md`:1765: er kommt von aussen, bei JEDEM Kommando.
    let anchor = anchor.ok_or(UsageError::MissingTrustAnchor)?;

    // 4 — Schalter, die dieses Kommando nicht kennt. Sie werden GLOBAL geparst
    // und HIER abgelehnt: ein Aufrufer, der `--key` an `verify` haengt, hat
    // sich vertan, und ein stilles Ignorieren liesse ihn glauben, der
    // Schluessel sei benutzt worden.
    if key.is_some() && command_kind != CommandKind::Decrypt {
        return Err(UsageError::SwitchNotAllowed {
            switch: KEY_SWITCH,
            command: command_name,
        });
    }
    if output.is_some() && matches!(command_kind, CommandKind::Verify | CommandKind::List) {
        return Err(UsageError::SwitchNotAllowed {
            switch: OUTPUT_SWITCH,
            command: command_name,
        });
    }
    let include_runtime_metadata = include_runtime_metadata.unwrap_or(false);
    if include_runtime_metadata && command_kind != CommandKind::Report {
        return Err(UsageError::SwitchNotAllowed {
            switch: INCLUDE_RUNTIME_METADATA_SWITCH,
            command: command_name,
        });
    }

    // 5 — genau ein Positionsargument, bei allen fuenf Kommandos.
    let mut positionals = positionals.into_iter();
    let path = positionals
        .next()
        .ok_or(UsageError::MissingPositional(command_name))?;
    if positionals.next().is_some() {
        return Err(UsageError::SurplusPositional(command_name));
    }

    // 6 — Schalter, die dieses Kommando verlangt.
    let command = match command_kind {
        CommandKind::Verify => Command::Verify { archive: path },
        CommandKind::List => Command::List { archive: path },
        CommandKind::Decrypt => Command::Decrypt {
            archive: path,
            key: key.ok_or(UsageError::MissingSwitch {
                switch: KEY_SWITCH,
                command: command_name,
            })?,
            output: output.ok_or(UsageError::MissingSwitch {
                switch: OUTPUT_SWITCH,
                command: command_name,
            })?,
        },
        CommandKind::Report => Command::Report {
            archive: path,
            output: output.ok_or(UsageError::MissingSwitch {
                switch: OUTPUT_SWITCH,
                command: command_name,
            })?,
        },
        CommandKind::Export => Command::Export {
            source: path,
            output: output.ok_or(UsageError::MissingSwitch {
                switch: OUTPUT_SWITCH,
                command: command_name,
            })?,
        },
    };

    Ok(Invocation {
        anchor,
        format: format.unwrap_or(Format::Text),
        include_runtime_metadata,
        command,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        Command, FORMAT_SWITCH, Format, INCLUDE_RUNTIME_METADATA_SWITCH, Invocation, KEY_SWITCH,
        OUTPUT_SWITCH, TRUST_ANCHOR_SWITCH, UsageError, parse,
    };
    use std::{ffi::OsString, path::PathBuf};

    /// Parst eine Argumentfolge OHNE Programmnamen und ohne Prozessstart.
    fn parsed(tokens: &[&str]) -> Result<Invocation, UsageError> {
        parse(tokens.iter().copied().map(OsString::from))
    }

    /// Der Aufruffehler dieser Argumentfolge.
    fn rejected(tokens: &[&str]) -> UsageError {
        parsed(tokens).expect_err("die Argumentfolge muss abgelehnt werden")
    }

    #[test]
    fn every_command_parses_in_its_full_form() {
        assert_eq!(
            parsed(&[TRUST_ANCHOR_SWITCH, "anchor.etb", "verify", "archive"])
                .expect("verify muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Text,
                include_runtime_metadata: false,
                command: Command::Verify {
                    archive: PathBuf::from("archive")
                },
            }
        );
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                FORMAT_SWITCH,
                "json",
                "list",
                "archive"
            ])
            .expect("list muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Json,
                include_runtime_metadata: false,
                command: Command::List {
                    archive: PathBuf::from("archive")
                },
            }
        );
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "decrypt",
                "archive",
                KEY_SWITCH,
                "recipient.key",
                OUTPUT_SWITCH,
                "target"
            ])
            .expect("decrypt muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Text,
                include_runtime_metadata: false,
                command: Command::Decrypt {
                    archive: PathBuf::from("archive"),
                    key: PathBuf::from("recipient.key"),
                    output: PathBuf::from("target"),
                },
            }
        );
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                INCLUDE_RUNTIME_METADATA_SWITCH,
                "report",
                "archive",
                OUTPUT_SWITCH,
                "report.json"
            ])
            .expect("report muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Text,
                include_runtime_metadata: true,
                command: Command::Report {
                    archive: PathBuf::from("archive"),
                    output: PathBuf::from("report.json"),
                },
            }
        );
        assert_eq!(
            parsed(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "export",
                "archive",
                OUTPUT_SWITCH,
                "target"
            ])
            .expect("export muss parsen"),
            Invocation {
                anchor: PathBuf::from("anchor.etb"),
                format: Format::Text,
                include_runtime_metadata: false,
                command: Command::Export {
                    source: PathBuf::from("archive"),
                    output: PathBuf::from("target"),
                },
            }
        );
    }

    /// Der Anker ist bei ALLEN FUENF Kommandos Pflicht, nicht nur bei `verify`.
    #[test]
    fn every_command_requires_the_trust_anchor() {
        for tokens in [
            vec!["verify", "archive"],
            vec!["list", "archive"],
            vec!["decrypt", "archive", KEY_SWITCH, "k", OUTPUT_SWITCH, "t"],
            vec!["report", "archive", OUTPUT_SWITCH, "r.json"],
            vec!["export", "archive", OUTPUT_SWITCH, "t"],
        ] {
            assert_eq!(
                rejected(&tokens),
                UsageError::MissingTrustAnchor,
                "{tokens:?} darf ohne Anker nicht durchgehen"
            );
        }
    }

    #[test]
    fn an_unknown_command_is_rejected_verbatim() {
        assert_eq!(
            rejected(&[TRUST_ANCHOR_SWITCH, "anchor.etb", "veriify", "archive"]),
            UsageError::UnknownCommand("veriify".to_owned())
        );
    }

    #[test]
    fn a_missing_positional_argument_is_rejected() {
        assert_eq!(
            rejected(&[TRUST_ANCHOR_SWITCH, "anchor.etb", "verify"]),
            UsageError::MissingPositional("verify")
        );
    }

    #[test]
    fn a_surplus_positional_argument_is_rejected() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "verify",
                "archive",
                "second"
            ]),
            UsageError::SurplusPositional("verify")
        );
    }

    #[test]
    fn a_missing_output_is_rejected_for_every_writing_command() {
        for command in ["decrypt", "report", "export"] {
            let mut tokens = vec![TRUST_ANCHOR_SWITCH, "anchor.etb", command, "archive"];
            if command == "decrypt" {
                tokens.extend([KEY_SWITCH, "recipient.key"]);
            }
            assert_eq!(
                rejected(&tokens),
                UsageError::MissingSwitch {
                    switch: OUTPUT_SWITCH,
                    command,
                },
                "{command} darf ohne {OUTPUT_SWITCH} nicht durchgehen"
            );
        }
    }

    #[test]
    fn a_missing_key_is_rejected_for_decrypt() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "decrypt",
                "archive",
                OUTPUT_SWITCH,
                "target"
            ]),
            UsageError::MissingSwitch {
                switch: KEY_SWITCH,
                command: "decrypt",
            }
        );
    }

    /// Auch die `--format=json`-Form: sie ist ausdruecklich KEIN Wert, sondern
    /// ein unbekannter Schalter.
    #[test]
    fn an_unknown_format_value_is_rejected() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                FORMAT_SWITCH,
                "yaml",
                "verify",
                "archive"
            ]),
            UsageError::UnknownFormat("yaml".to_owned())
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "--format=json",
                "verify",
                "archive"
            ]),
            UsageError::UnknownSwitch("--format=json".to_owned())
        );
    }

    /// Sowohl am Ende der Zeile als auch vor dem naechsten Schalter.
    #[test]
    fn a_switch_without_a_value_is_rejected() {
        assert_eq!(
            rejected(&[TRUST_ANCHOR_SWITCH]),
            UsageError::MissingValue(TRUST_ANCHOR_SWITCH)
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "report",
                "archive",
                OUTPUT_SWITCH,
                FORMAT_SWITCH,
                "json"
            ]),
            UsageError::MissingValue(OUTPUT_SWITCH)
        );
    }

    /// Auch das Flag zaehlt: doppelt gesetzt ist doppelt gesetzt.
    #[test]
    fn a_duplicated_switch_is_rejected() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "one.etb",
                TRUST_ANCHOR_SWITCH,
                "two.etb",
                "verify",
                "archive"
            ]),
            UsageError::DuplicateSwitch(TRUST_ANCHOR_SWITCH)
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                FORMAT_SWITCH,
                "text",
                FORMAT_SWITCH,
                "json",
                "verify",
                "archive"
            ]),
            UsageError::DuplicateSwitch(FORMAT_SWITCH)
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                INCLUDE_RUNTIME_METADATA_SWITCH,
                INCLUDE_RUNTIME_METADATA_SWITCH,
                "report",
                "archive",
                OUTPUT_SWITCH,
                "report.json"
            ]),
            UsageError::DuplicateSwitch(INCLUDE_RUNTIME_METADATA_SWITCH)
        );
    }

    /// `--include-runtime-metadata` ist der EINZIGE Weg zu
    /// nichtdeterministischen Berichtsfeldern und gehoert deshalb genau einem
    /// Kommando.
    #[test]
    fn runtime_metadata_is_rejected_outside_report() {
        for command in ["verify", "list", "decrypt", "export"] {
            let mut tokens = vec![
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                INCLUDE_RUNTIME_METADATA_SWITCH,
                command,
                "archive",
            ];
            if command == "decrypt" {
                tokens.extend([KEY_SWITCH, "recipient.key"]);
            }
            if command == "decrypt" || command == "export" {
                tokens.extend([OUTPUT_SWITCH, "target"]);
            }
            assert_eq!(
                rejected(&tokens),
                UsageError::SwitchNotAllowed {
                    switch: INCLUDE_RUNTIME_METADATA_SWITCH,
                    command,
                },
                "{command} darf {INCLUDE_RUNTIME_METADATA_SWITCH} nicht annehmen"
            );
        }
    }

    /// Ein `--key` an einem Kommando, das nichts entschluesselt, ist ein
    /// Irrtum ueber den Lauf und wird nicht stillschweigend verworfen.
    #[test]
    fn a_switch_of_another_command_is_rejected() {
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "verify",
                "archive",
                KEY_SWITCH,
                "recipient.key"
            ]),
            UsageError::SwitchNotAllowed {
                switch: KEY_SWITCH,
                command: "verify",
            }
        );
        assert_eq!(
            rejected(&[
                TRUST_ANCHOR_SWITCH,
                "anchor.etb",
                "list",
                "archive",
                OUTPUT_SWITCH,
                "target"
            ]),
            UsageError::SwitchNotAllowed {
                switch: OUTPUT_SWITCH,
                command: "list",
            }
        );
    }

    #[test]
    fn an_empty_argument_list_is_its_own_case() {
        assert_eq!(rejected(&[]), UsageError::NoArguments);
        assert_eq!(
            rejected(&[TRUST_ANCHOR_SWITCH, "anchor.etb"]),
            UsageError::MissingCommand
        );
    }

    /// Ein Pfadwert geht unbesehen durch, ein Schaltername nicht.
    #[test]
    fn path_values_survive_non_utf8_but_switch_names_do_not() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;

            let raw = OsString::from_vec(vec![b'a', 0xff, b'r']);
            let invocation = parse(
                [
                    OsString::from(TRUST_ANCHOR_SWITCH),
                    OsString::from("anchor.etb"),
                    OsString::from("verify"),
                    raw.clone(),
                ]
                .into_iter(),
            )
            .expect("ein nicht-UTF-8-Pfad muss durchgehen");
            assert_eq!(
                invocation.command,
                Command::Verify {
                    archive: PathBuf::from(raw)
                }
            );

            let raw_switch = OsString::from_vec(vec![b'-', b'-', 0xff]);
            assert!(matches!(
                parse([raw_switch].into_iter()),
                Err(UsageError::UnknownSwitch(_))
            ));
        }
    }
}

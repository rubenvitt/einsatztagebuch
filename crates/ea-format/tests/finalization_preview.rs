//! Die vierte und letzte Hashregel, die Stufe 2 festschreibt: das Urbild der
//! Abschlussvorschau.
//!
//! Die Digests werden gegen den FRISCH gerechneten Digest der kodierten Bytes
//! gestellt und niemals gegen ein Literal. Der Test sagt damit die REGEL und
//! nicht ihre Abschrift: ein umbenanntes Feld, eine vertauschte Position und
//! ein wirkungsloser Wert fallen alle auf, waehrend ein Literal nur belegte,
//! dass jemand die Zahl abgeschrieben hat.

mod support;

#[test]
fn the_preview_core_carries_the_thirteen_positions_and_the_extension_slot() {
    let core = support::preview_core();
    let bytes = ea_format::encode_finalization_preview_core(&core).unwrap();
    assert!(ea_cbor::validate(&bytes, ea_cbor::ParserLimits::V1).is_ok());
    assert_eq!(support::array_length(&bytes), 13);
    assert!(support::last_position_is_an_empty_array(&bytes));
}

#[test]
fn every_position_of_the_preview_core_changes_the_preview_hash() {
    // `.as_bytes()` und nicht der Hashtyp selbst: `Hash32` traegt in Stufe 1
    // absichtlich kein `Debug`, und `assert_ne!` verlangt eines. Die Aussage
    // ist dieselbe — verglichen werden alle 32 Bytes.
    let base = *ea_crypto::finalization_preview_digest(
        &ea_format::encode_finalization_preview_core(&support::preview_core()).unwrap(),
    )
    .as_bytes();
    let mutated = support::preview_core_with_one_position_changed();
    // Die ELF offenen Positionen der Grammatik. Position eins ist das
    // Versionsliteral und Position dreizehn die leere Erweiterungsliste; beide
    // schreibt der Kodierer selbst, also ist ueber einen KERN keine Mutante
    // davon baubar. Genau diese zwei traegt der Test darueber: dreizehn
    // Positionen, letzte leer.
    //
    // Die Zusicherung ueber die LAENGE steht hier, weil eine schrumpfende
    // Hilfsfunktion sonst still weniger prueft und die Schleife gruen bliebe.
    assert_eq!(
        mutated.len(),
        11,
        "jede offene Position der Grammatik braucht ihre eigene Mutante"
    );
    for mutated in mutated {
        assert_ne!(
            *ea_crypto::finalization_preview_digest(
                &ea_format::encode_finalization_preview_core(&mutated).unwrap()
            )
            .as_bytes(),
            base,
            "eine Position ohne Wirkung waere eine Luecke in der Bestaetigung"
        );
    }
}

#[test]
fn a_null_predecessor_and_a_present_predecessor_are_distinguishable() {
    let genesis =
        ea_format::encode_finalization_preview_core(&support::preview_core_genesis()).unwrap();
    let successor = ea_format::encode_finalization_preview_core(&support::preview_core()).unwrap();
    assert_ne!(
        *ea_crypto::finalization_preview_digest(&genesis).as_bytes(),
        *ea_crypto::finalization_preview_digest(&successor).as_bytes()
    );
}

#[test]
fn the_preview_core_carries_no_content_and_no_path() {
    let bytes = ea_format::encode_finalization_preview_core(&support::preview_core()).unwrap();
    assert!(!ea_testkit::contains_canary(
        &bytes,
        b"CANARY-INCIDENT-TEXT"
    ));
    assert!(!ea_testkit::contains_canary(&bytes, b"CANARY-OUTPUT-PATH"));
    assert!(!ea_testkit::contains_canary(
        &bytes,
        b"CANARY-OPERATOR-NAME"
    ));
    // Die drei Kanarienvoegel allein KOENNEN nicht fallen: der Typ hat kein
    // Feld, in das ein Test sie legen koennte. Die falsifizierbare Haelfte der
    // Zusage ist die Aussage ueber die FORM jeder Position — kein Textstring,
    // kein gefuellter Behaelter. Eine spaeter angehaengte Freitext- oder
    // Pfadposition faellt hier, und zwar OHNE dass jemand einen neuen
    // Kanarienvogel erfindet.
    assert!(
        support::every_preview_position_is_a_fixed_width_scalar(&bytes),
        "eine Position, die Text oder einen gefuellten Behaelter tragen kann, \
         kann Inhalt und Pfad tragen"
    );
}

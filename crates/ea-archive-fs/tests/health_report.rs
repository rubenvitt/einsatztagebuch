//! Der Gesundheitscheck: zehn Befunde, zehn eigene Erkennungen.
//!
//! Die Zehn ist STRUKTURELL und keine Absprache: der Test laeuft ueber
//! [`HealthFinding::ALL`] und verlangt fuer jeden Arm ein Szenario, das genau
//! ihn erzeugt. Faellt ein Erkenner weg, wird der Test rot statt stiller.

mod support;

use ea_archive_fs::HealthFinding;

#[test]
fn an_intact_archive_yields_an_empty_report() {
    let scenario = support::intact_health_scenario();
    let report = scenario.run();
    assert!(
        report.is_empty(),
        "ein unversehrter Bestand hat KEINEN Befund: {:?}",
        report.findings()
    );
}

#[test]
fn every_health_finding_has_its_own_detection() {
    for finding in HealthFinding::ALL {
        let scenario = support::health_scenario_for(finding);
        let report = scenario.run();
        assert!(
            report.contains(finding),
            "{finding:?} MUSS von seinem eigenen Szenario erkannt werden; erkannt wurde {:?}",
            report.findings()
        );
    }
}

#[test]
fn every_finding_carries_a_distinct_stable_code() {
    let codes = HealthFinding::ALL
        .iter()
        .map(|finding| finding.code())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(codes.len(), HealthFinding::ALL.len());
    assert_eq!(HealthFinding::ALL.len(), 10);
    for code in codes {
        assert!(
            code.starts_with("EA-ARCHIVE-HEALTH-"),
            "{code} muss als Gesundheitsbefund erkennbar sein"
        );
    }
}

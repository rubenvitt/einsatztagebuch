# ADR 0007 — Offline-PKCS#11-Anbindung

## Status

Implementierungsentscheidung für DRK-250 vom 2026-09-08. Die unabhängige Prüfung
des Providers ist innerhalb des unten beschriebenen OID-Profils abgeschlossen.
Die vollständigen Integrationsgates stehen noch aus; dies ist keine Hardware-
oder Betriebsfreigabe.

## Entscheidung

`ea-recovery` lädt ausschließlich die explizit angegebene Modulbibliothek und
wählt darin genau das benannte Token und die konkrete Objekt-ID. Kein
Standardmodul, kein erstes Token und keine Suche nach privaten Schlüsseln auf
anderen Medien. Mehrdeutige Labels oder IDs werden verweigert. Die bestehende
PIN-Dateiprüfung erfolgt vor dem Laden; PIN und Modulfehler werden nicht geloggt.

Die Anbindung verwendet [`cryptoki 0.12.0`](https://github.com/parallaxsecond/rust-cryptoki/tree/cryptoki-0.12.0)
ohne Default- oder `generate-bindings`-Features. Die öffentliche sichere API
kapselt FFI und dynamisches Laden; das eigene `forbid(unsafe_code)` bleibt
unverändert. Die fest aufgelösten neuen Bibliotheken sind `cryptoki-sys 0.5.0`,
`libloading 0.8.9` und `secrecy 0.10.3`; bestehende `bitflags`, `log` und
`zeroize` werden weiterverwendet. Upstream nennt MSRV 1.77 für cryptoki und
Apache-2.0. `libloading` verwendet ISC und erhält eine namentliche Ausnahme
in `deny.toml`. Die vollständige finale Cargo-Deny-Prüfung bleibt erforderlich.
Der separat frisch geladene RustSec-Stand
`bf25f6575a93a35f30796c65c0ed91bee7fa19fd` enthält keine Paketmeldungen für diese
Familien; das ist keine pauschale Sicherheitszusage.

Eine lokale Kopie der gepinnten `cryptoki`-Quelle enthält ausschließlich einen
Patch für zeroisierende Zwischenpuffer in `Session::get_attributes`.
Upstream kopiert die gelesenen Attribute in das Ergebnis und gibt den
verborgenen Zwischenpuffer ohne Überschreiben frei; der Aufrufer kann diese
DH-Kopie nicht selbst bereinigen. Drei Pufferzeilen verwenden nun das bereits
gepinnt vorhandene `zeroize 1.9.0`. Herkunft, Lizenz und der genaue Umfang
stehen in `vendor/cryptoki/EINSATZARCHIV-PATCH.md`. FFI und Mechanismen bleiben
unverändert; die Aufrufer bereinigen weiterhin ihre eigenen Ergebnisse.

Langlebige private Schlüssel werden nie über `CKA_VALUE` gelesen. Vor jeder
Operation müssen Schlüsselart, Kurvenparameter, Private/Sensitive/Extractable
und die jeweilige Verwendung passen. Eine gemeinsam geprüfte öffentliche
Schlüsselhälfte bestimmt den COSE-Abdruck; die fertige Signatur bzw. HPKE-
Entschlüsselung muss dazu passen. Ein wechselndes Objekt unter derselben ID
erhält keine alte Berechtigung.

X25519 verwendet `CKM_ECDH1_DERIVE` mit `CKD_NULL`. Nur das kurzlebige
DH-Ergebnis wird als Sitzungsschlüssel lesbar erzeugt, sofort in einen
zeroisierenden Träger überführt und das Tokenobjekt vor Rückgabe zerstört.
`ea-crypto` übernimmt die bestehende RFC-9180-DHKEM-Kontextbindung und
Schlüsselableitung über die gepinnte HPKE-Bibliothek. Es entsteht keine zweite
HKDF-/AEAD-Implementierung. Ein Null-DH-Ergebnis und unpassende Info/AAD werden
abgewiesen. Recovery-KEM und HGA-Signatur bleiben getrennte Ports.

Ed25519 signiert nur die von `ea-crypto::ExternalCoseSigningRequest`
konstruierte bestehende historische Grant-Signatur oder den bestehenden
Recovery-Testnachweis. Es gibt keinen öffentlichen beliebigen Digest-/Header-
Signierpfad. Die Rücksignatur wird mit dem erwarteten öffentlichen Schlüssel
verifiziert, bevor die exakten COSE-Bytes zurückgegeben werden.

Jeder Zugriff hat einen vollständig abgeschlossenen Modul-/Sitzungslebenslauf
mit frischer PIN-Anmeldung und Abmeldung. Eine Prozesssperre verhindert, dass
gleichzeitige KEM-/HGA-Aufrufe den tokenweiten Login oder `C_Finalize` teilen.
„Bereits angemeldet“ ersetzt keine PIN-Prüfung. Fehlerhafte Abmeldung/
Finalisierung gibt kein Erfolgsergebnis frei. PKCS#11-Module sind explizit
installierter nativer Code; das ist kein Sandbox-Versprechen für beliebige
Bibliotheken.

## Modulprofil und Nachweise

Das Standardprofil verlangt die OIDs `1.3.101.110` (X25519) bzw. `1.3.101.112`
(Ed25519), dazu Montgomery- bzw. Edwards-KeyType. Das ausdrücklich geprüfte
SoftHSM-2.7-Profil bildet auch X25519 als Edwards-KeyType ab und wird nur bei
passender Modulidentität plus exakter X25519-OID zugelassen. Eine beliebige
Edwards-Kurve wird dadurch nicht als X25519 interpretiert.

SoftHSM-generierte Ed25519-Schlüssel mit DER-PrintableString `edwards25519`
statt der OID werden aktuell abgewiesen. Die geprüfte Fixture importiert
OID-parametrisierte Schlüssel; sie belegt keine allgemeine Kompatibilität mit
jeder nativen Schlüsselerzeugung oder jedem Tokenprofil.

Die lokale Fixture baut [SoftHSM 2.7.0](https://github.com/softhsm/SoftHSMv2/tree/2.7.0)
aus dem Tagarchiv, SHA-256
`be14a5820ec457eac5154462ffae51ba5d8a643f6760514d4b4b83a77be91573`.
Ihre Konfiguration und Token liegen isoliert im Arbeitsverzeichnis. Der reale
Modullauf hat X25519-Ableitung, Ed25519-Signatur, Sensitive=true,
Extractable=false und verweigerten privaten Value-Zugriff bestätigt. Er ist
auch durch den Produktresolver mit frischer Anmeldung, falscher PIN/ID/Art,
HPKE-Kontextfehler und anschließender Wiederholung bestätigt. Die reproduzierbare
Containerfixture und umfassenden Produkt-/Canary-Tests gehören zur Integration.

Die Krypto-Anschlüsse stimmen mit den bestehenden exakten Suite-v1-Bytes
überein. Providerprüfung umfasst außerdem falsche PIN/ID/Schlüsselart,
Mehrdeutigkeit, geänderte öffentliche Zuordnung, Wiederholung und dauerhafte
Bereinigung abgeleiteter Sitzungsobjekte. Physische HSM-Verwahrung und die
installierte Drei-Plattform-Abnahme bleiben eigene Nachweise.

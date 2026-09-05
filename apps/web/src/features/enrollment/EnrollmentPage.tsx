import { Alert, Button, ConfigProvider, Space, Tag, Typography } from 'antd'
import deDE from 'antd/locale/de_DE'
import { useEffect, useRef, useState } from 'react'
import type { ReactElement } from 'react'

import { DecorativeIcon } from '../../design/icons'
import { eaRuntimeTheme } from '../../design/tokens'
import type {
  EnrollmentBridge,
  EnrollmentFingerprintsStatusV1,
  FingerprintConfirmationStatusV1,
} from '../../vault/webauthn-prf'
import { enrollmentBridge } from '../../vault/webauthn-prf'
import { readerSessionBridge } from '../session/reader-session'
import { AuthenticatorRegistration } from './AuthenticatorRegistration'
import { FingerprintGate } from './FingerprintGate'

/**
 * Die Enrollment-Fläche: zwei Pflicht-Authenticators und das nicht
 * überspringbare Fingerprint-Gate (`web-reader-design.md` §6.3 und §4.3).
 *
 * TypeScript trifft hier KEINE Sicherheitsentscheidung (§9). Diese Datei
 * leitet keinen Schlüssel ab, vergleicht keinen Fingerprint und entscheidet
 * keine Weigerung — sie zeigt an, nimmt entgegen und ruft. Jede der drei
 * Zusagen, die man ihr ansehen kann, gehört jemand anderem:
 *
 * - Die Kardinalität gehört der Brücke: `registered` und `required` kommen aus
 *   `enrollmentRegisterAuthenticator`, nicht aus einem Zähler dieser Datei.
 * - Der Vergleich gehört `ea-reader`: `confirmFingerprints` gibt ein Ergebnis
 *   zurück, und `confirmed` ist dessen Wert, nicht das Ergebnis einer
 *   Zeichenkettenprobe hier.
 * - Die Unüberspringbarkeit gehört dem TYP: `finish` verlangt in Rust eine
 *   `FingerprintConfirmationV1`, und die kann die Grenze nach JavaScript nicht
 *   überqueren. Das gesperrte Abschlusselement ist die Höflichkeit davor, nicht
 *   das Gate.
 *
 * Die Fläche benutzt ausschliesslich Ant-Komponenten, die
 * `EXTRACTED_COMPONENTS` in `apps/web/src/design/extract-static-css.tsx`
 * bereits führt. `Form` und `Steps` stehen dort NICHT, und ein Import von
 * ihnen färbte `extracts every Ant component the hand written sources import`
 * rot — die Reparatur zöge eine neu erzeugte `static-antd.css` in eine
 * Aufgabe, deren Gegenstand das Enrollment ist.
 */
export type EnrollmentPageProps = {
  readonly bridge?: EnrollmentBridge
}

/**
 * Der stabile Code der EINEN Weigerung, die diese Fläche in eigenen Worten
 * beantwortet.
 *
 * Er steht hier als Literal und nicht als Datum aus der Brücke, weil keine der
 * fünf Ausfuhren ihn herausgibt — er reist als Wurf. Er ist ein
 * Anschriftschlüssel für einen Satz und keine Sicherheitsentscheidung (§9):
 * entschieden hat `ReaderEnrollment::begin`, hier wird die Entscheidung nur
 * lesbar gemacht.
 */
const VAULT_PRESENT_CODE = 'EA-READER-ENROLLMENT-VAULT-PRESENT'

/**
 * Der Fehlschlag in Worten, die jemand ohne Kenntnis der Codes lesen kann.
 *
 * Nur für die Weigerung, die den häufigsten Weg trifft: das Gerät hat sein
 * Enrollment längst abgeschlossen, und jemand ruft `/enrollment` ein zweites
 * Mal auf. Ein blanker Code ließe an dieser Stelle offen, ob etwas kaputt ist
 * oder ob alles seine Ordnung hat. Jeder andere Fehlschlag bleibt der
 * unveränderte Text — ein erfundener Satz über eine Lage, die diese Datei nicht
 * kennt, wäre schlechter als der Code.
 */
function failureText(reason: unknown): string {
  const text = String(reason)
  if (text.includes(VAULT_PRESENT_CODE)) {
    return (
      'Dieses Gerät trägt bereits einen Reader-Tresor. Ein neues Enrollment würde zwei frische ' +
      'Passkeys anlegen und dabei den Passkey des vorhandenen Tresors ersetzen — es wird deshalb ' +
      'abgelehnt. Zum Weiterarbeiten entsperre den vorhandenen Tresor; ein zweites Enrollment auf ' +
      'diesem Gerät richtet die Administration ein.'
    )
  }
  return text
}

export function EnrollmentPage({ bridge = enrollmentBridge }: EnrollmentPageProps = {}): ReactElement {
  const [handle, setHandle] = useState<number | undefined>(undefined)
  const [registered, setRegistered] = useState(0)
  const [required, setRequired] = useState(0)
  const [shown, setShown] = useState<EnrollmentFingerprintsStatusV1 | undefined>(undefined)
  const [expectedKeyFingerprint, setExpectedKeyFingerprint] = useState('')
  const [expectedBundleFingerprint, setExpectedBundleFingerprint] = useState('')
  const [confirmation, setConfirmation] = useState<FingerprintConfirmationStatusV1 | undefined>(
    undefined,
  )
  const [registering, setRegistering] = useState(false)
  const [finished, setFinished] = useState(false)
  const [unlocked, setUnlocked] = useState(false)
  const [failure, setFailure] = useState<string | undefined>(undefined)

  // Der Anlauf läuft GENAU EINMAL je Montage. Der Wächter ist eine Referenz und
  // kein Abbruchmerker: unter `StrictMode` ruft React 19 den Effekt in der
  // Entwicklung zweimal, und ein zweites `begin` legte ein zweites Enrollment
  // mit einem zweiten Schlüsselpaar an — sichtbar erst daran, dass der
  // angezeigte Schlüssel-Fingerprint nicht der ist, den `finish` versiegelt.
  const started = useRef(false)
  useEffect(() => {
    if (started.current) {
      return
    }
    started.current = true
    void (async () => {
      try {
        const began = await bridge.begin()
        setHandle(began.handle)
        setShown(await bridge.fingerprints({ handle: began.handle }))
      } catch (error) {
        setFailure(failureText(error))
      }
    })()
  }, [bridge])

  // Gefragt wird die Brücke, sobald die abgetippte Referenz dieselbe LÄNGE hat
  // wie der angezeigte Wert. Die Länge kommt aus dem angezeigten Wert und steht
  // hier nicht als Zahl; sie entscheidet nur, WANN gefragt wird, und niemals,
  // WAS herauskommt. Bei jeder anderen Länge fällt die Bestätigung zurück auf
  // „nicht bestätigt", damit ein einmal erreichtes Ja nicht stehen bleibt,
  // während der Wert daneben weiterwandert.
  useEffect(() => {
    if (handle === undefined || shown === undefined) {
      return
    }
    if (
      expectedKeyFingerprint.length !== shown.keyFingerprint.length ||
      expectedBundleFingerprint.length !== shown.bundleFingerprint.length
    ) {
      setConfirmation(undefined)
      return
    }
    let current = true
    void (async () => {
      try {
        const answer = await bridge.confirmFingerprints({
          handle,
          expectedKeyFingerprint,
          expectedBundleFingerprint,
        })
        if (current) {
          setConfirmation(answer)
        }
      } catch (error) {
        if (current) {
          setFailure(failureText(error))
        }
      }
    })()
    return () => {
      current = false
    }
  }, [bridge, handle, shown, expectedKeyFingerprint, expectedBundleFingerprint])

  const confirmed = confirmation?.confirmed === true
  const enoughAuthenticators = required > 0 && registered >= required
  const mayFinish = enoughAuthenticators && confirmed && !finished

  return (
    <ConfigProvider locale={deDE} theme={eaRuntimeTheme}>
      <section aria-label="Enrollment">
        <Space orientation="vertical" size="middle">
          <Space size="small">
            <DecorativeIcon name="locked" />
            <Typography.Title level={2}>Enrollment</Typography.Title>
          </Space>
          {failure === undefined ? null : (
            <Alert type="error" showIcon title="Das Enrollment ist gescheitert." description={failure} />
          )}
          <AuthenticatorRegistration
            registered={registered}
            required={required}
            busy={registering}
            onRegister={() => {
              // Der Wächter steht VOR dem Aufruf und nicht nur am
              // Bedienelement: ein gesperrter Knopf ist die Höflichkeit, dieser
              // Zweig ist die Bedingung. Solange eine Zeremonie läuft, ist der
              // Satz aufgenommener Kennungen in der Brücke noch der alte, und
              // ein zweiter Anlauf ginge mit einem zu kurzen
              // `excludeCredentials` los.
              if (handle === undefined || registering) {
                return
              }
              setRegistering(true)
              void (async () => {
                try {
                  const count = await bridge.registerAuthenticator({ handle })
                  setRegistered(count.registered)
                  setRequired(count.required)
                } catch (error) {
                  setFailure(failureText(error))
                } finally {
                  setRegistering(false)
                }
              })()
            }}
          />
          <FingerprintGate
            keyFingerprint={shown?.keyFingerprint ?? ''}
            bundleFingerprint={shown?.bundleFingerprint ?? ''}
            expectedKeyFingerprint={expectedKeyFingerprint}
            expectedBundleFingerprint={expectedBundleFingerprint}
            confirmed={confirmed}
            refusalCode={confirmation?.confirmed === false ? confirmation.code : undefined}
            onExpectedKeyFingerprintChange={setExpectedKeyFingerprint}
            onExpectedBundleFingerprintChange={setExpectedBundleFingerprint}
          />
          <section aria-label="Abschluss">
            <Space orientation="vertical" size="small">
              <Space size="small">
                <Tag>Schritt 3</Tag>
                <Typography.Title level={3}>Abschluss</Typography.Title>
              </Space>
              <Button
                type="primary"
                disabled={!mayFinish}
                onClick={() => {
                  if (handle === undefined) {
                    return
                  }
                  void (async () => {
                    try {
                      const status = await bridge.finish({ handle })
                      setFinished(status.finished)
                    } catch (error) {
                      setFailure(failureText(error))
                    }
                  })()
                }}
              >
                Enrollment abschließen
              </Button>
              {finished ? (
                <Space orientation="vertical" size="small">
                  <Space size="small">
                    <DecorativeIcon name="verified" state="confirmed" />
                    <Typography.Text>Enrollment abgeschlossen.</Typography.Text>
                  </Space>
                  {/*
                    Die LEBENDE Paritätsprobe: derselbe Authenticator wird ein
                    zweites Mal befragt, und der Tresor, den dieser Lauf gebaut
                    hat, muss sich mit dem öffnen, was dabei herauskommt. Keine
                    sechste Brückenausfuhr, sondern der Weg, den die Crate
                    schon hat — und zwar über den EINEN Halter der
                    Sitzungskennung: eine hier eröffnete und fallengelassene
                    Sitzung bekäme keine Meldung der Haken aus `main.tsx`
                    (§6.5). Die Uhr der Seite tritt als WERT ein, wie überall.
                  */}
                  <Button
                    onClick={() => {
                      void (async () => {
                        try {
                          await readerSessionBridge.unlock(Date.now())
                          setUnlocked(true)
                        } catch (error) {
                          setFailure(failureText(error))
                        }
                      })()
                    }}
                  >
                    Tresor entsperren
                  </Button>
                  {unlocked ? (
                    <Space size="small">
                      <DecorativeIcon name="verified" state="confirmed" />
                      <Typography.Text>Tresor entsperrt.</Typography.Text>
                    </Space>
                  ) : null}
                </Space>
              ) : null}
            </Space>
          </section>
        </Space>
      </section>
    </ConfigProvider>
  )
}

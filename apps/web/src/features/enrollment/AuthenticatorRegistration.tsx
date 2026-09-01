import { Button, Space, Tag, Typography } from 'antd'
import type { ReactElement } from 'react'

import { DecorativeIcon } from '../../design/icons'

/**
 * Der ZWEITE Schritt des Enrollments: zwei Pflicht-Authenticators.
 *
 * Der Zaehler wird NICHT hier gefuehrt. `registered` und `required` kommen
 * beide aus der Bruecke — `required` ist `MIN_ENROLLED_AUTHENTICATORS_V1` aus
 * geteiltem Rust —, und diese Datei zaehlt keine Klicks: eine Oberflaeche, die
 * ihre eigene Kardinalitaet fuehrte, koennte zwei melden, wo Rust eins
 * gezaehlt hat (§9).
 */
export type AuthenticatorRegistrationProps = {
  readonly registered: number
  readonly required: number
  /**
   * Laeuft gerade eine Zeremonie?
   *
   * Solange sie laeuft, ist das Bedienelement GESPERRT. Der Grund ist der
   * Spiegel der aufgenommenen Kennungen: er wird erst aus der Antwort von
   * `registerAuthenticator` gestellt, ein zweiter Klick davor ginge also mit
   * dem ALTEN, zu kurzen Satz in `excludeCredentials` — auf einem Geraet, das
   * die fehlende Kennung schon traegt, ersetzte die Zeremonie dann den ersten
   * Passkey, statt abgewiesen zu werden. Chromium laesst heute ohnehin nur eine
   * ausstehende `credentials.create`-Anfrage zu, aber dieser Schutz gehoert dem
   * BROWSER und nicht dieser Anwendung.
   */
  readonly busy: boolean
  readonly onRegister: () => void
}

/**
 * Der Stand als TEXT und nicht als Symbol oder Farbe.
 *
 * Die fehlende Zahl wird beim Namen genannt: „noch keiner" und „ein zweiter"
 * sind zwei verschiedene Lagen, und ein gemeinsamer Satz („nicht genug")
 * verschwiege, welche gerade gilt.
 */
function registrationText(registered: number, required: number): string {
  if (registered === 0) {
    return 'Noch kein Authenticator registriert.'
  }
  if (registered < required) {
    return 'Ein zweiter Authenticator ist erforderlich.'
  }
  return `${registered} von ${required} Authenticators registriert.`
}

export function AuthenticatorRegistration({
  registered,
  required,
  busy,
  onRegister,
}: AuthenticatorRegistrationProps): ReactElement {
  const complete = required > 0 && registered >= required
  return (
    <section aria-label="Authenticators">
      <Space orientation="vertical" size="small">
        <Space size="small">
          <Tag>Schritt 1</Tag>
          <Typography.Title level={3}>Authenticators registrieren</Typography.Title>
        </Space>
        <Typography.Paragraph>
          Ein Enrollment braucht zwei Authenticators. Der zweite ist kein Ersatzweg für den
          Notfall, sondern der Grund, warum ein verlorener Passkey den Zugang nicht mitnimmt.
        </Typography.Paragraph>
        <Space size="small">
          <DecorativeIcon name={complete ? 'verified' : 'locked'} state={complete ? 'confirmed' : 'default'} />
          <Typography.Text>{registrationText(registered, required)}</Typography.Text>
        </Space>
        <Button disabled={busy} onClick={onRegister}>
          Authenticator registrieren
        </Button>
      </Space>
    </section>
  )
}

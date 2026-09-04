import { Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import type { ReaderTechnicalView } from '../../bridge/generated-contracts'
import { FingerprintBlock } from '../../components/integrity/FingerprintBlock'
import { ServerConfirmationStatus, StatusDimension } from './StatusDimension'

/**
 * Die technische Ansicht EINES Eintrags aus `design.md` §17.2 — jeder Wert aus
 * `ReaderTechnicalView`, jeder mit dem Satz daneben, der sagt, was er ist.
 *
 * Diese Flaeche erklaert und rechnet nicht: sie vergleicht keinen Hash,
 * prueft keine Kette und leitet aus keinem Wert einen Zustand ab. Was hier
 * steht, hat der Bericht in Rust festgestellt.
 *
 * Der Writer-Key dieser Ansicht ist der Hash des Writer-Zertifikats aus dem
 * Manifest — einen eigenen Thumbprint des Writer-Schluessels traegt der
 * Vertrag nicht, weil kein Erzeuger ihn liefert. Und die Evidence ist ein
 * BEFUNDCODE oder `null` — `report.evidence_errors()` unter dem Objekthash
 * dieses Eintrags. Sie steht deshalb an einem eigenen `StatusDimension` und
 * NICHT in `EvidenceStatus`: dessen nicht-`null`-Zweig rendert eine gruene
 * Erfolgsmarke unter „Evidenzstufe", und ein Befund der Pruefung als
 * bestandene Stufe waere die falsche Aussage. Eine Stufe, die niemand
 * festgestellt hat, wird hier nicht behauptet.
 */
export function TechnicalView({ view }: { readonly view: ReaderTechnicalView }): ReactElement {
  return (
    <section aria-label="Technische Ansicht">
      <Space orientation="vertical" size="middle">
        <Typography.Title level={3}>Technische Ansicht</Typography.Title>

        <Space orientation="vertical" size="small">
          <Typography.Text strong>Sequenz {view.sequence}</Typography.Text>
          <Typography.Text type="secondary">
            Die Stelle des Eintrags in der Kette des Writers. Jede Sequenz ist an ihren Vorgänger
            gebunden und wird nie wiederverwendet.
          </Typography.Text>
        </Space>

        <Space orientation="vertical" size="small">
          {view.previousEntryHash === null ? (
            <Typography.Text>
              Kein vorheriger Eintragshash: dieser Eintrag ist der erste der Kette.
            </Typography.Text>
          ) : (
            <FingerprintBlock
              entries={[{ label: 'Vorheriger Eintragshash', value: view.previousEntryHash }]}
            />
          )}
          <FingerprintBlock
            entries={[
              { label: 'Eintragshash', value: view.entryHash },
              { label: 'Chiffrat-Hash', value: view.ciphertextHash },
            ]}
          />
          <Typography.Text type="secondary">
            Der vorherige Eintragshash verkettet diesen Eintrag mit seinem Vorgänger; der
            Eintragshash ist seine eigene Kennung; der Chiffrat-Hash gehört zu den verschlüsselten
            Bytes, wie sie im Archiv liegen. Alle drei hat die Verifikation gegen das Manifest
            geprüft.
          </Typography.Text>
        </Space>

        <Space orientation="vertical" size="small">
          <FingerprintBlock
            entries={[{ label: 'Writer-Zertifikat', value: view.writerCertificateHash }]}
          />
          <Typography.Text type="secondary">
            Der Hash des Zertifikats, mit dem der Writer dieses Manifest signiert hat. Ob es zum
            Zeitpunkt der Signatur gültig war, hat die Registry-Prüfung entschieden.
          </Typography.Text>
        </Space>

        <Space orientation="vertical" size="small">
          <Typography.Text strong>Registry-Version {view.registryVersion}</Typography.Text>
          <FingerprintBlock entries={[{ label: 'Registry-Kopf', value: view.registryHeadHash }]} />
          <Typography.Text type="secondary">
            Der Stand der Registry, an den dieser Eintrag gebunden ist: welche Geräte und Rollen
            zu diesem Zeitpunkt galten. Version und Kopf-Hash gehören zusammen.
          </Typography.Text>
        </Space>

        <Space orientation="vertical" size="small">
          <ServerConfirmationStatus value={view.serverConfirmation} />
          <Typography.Text type="secondary">
            Eine Serverquittung bestätigt, dass der Sync-Server denselben Eintrag gesehen hat.
            Sie ist keine Bedingung der Verifikation.
          </Typography.Text>
        </Space>

        <Space orientation="vertical" size="small">
          {view.evidenceDetailCode === null ? (
            <StatusDimension
              label="Evidence-Prüfung"
              value="keine Beanstandung im Verifikationslauf"
              color="default"
            />
          ) : (
            <StatusDimension
              label="Evidence-Prüfung"
              value={view.evidenceDetailCode}
              color="warning"
              description="Befundcode der Evidence-Prüfung"
            />
          )}
          <Typography.Text type="secondary">
            Trägt der Bericht zu diesem Eintrag einen Evidence-Befund, steht hier sein Code; sonst
            steht hier, dass es keinen gibt. Eine Stufe der Evidenz stellt der Reader nicht fest und
            behauptet deshalb keine.
          </Typography.Text>
        </Space>
      </Space>
    </section>
  )
}

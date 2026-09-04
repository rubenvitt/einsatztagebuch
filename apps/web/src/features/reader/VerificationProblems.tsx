import { Space, Typography } from 'antd'
import type { ReactElement } from 'react'

import type { VerificationProblemView } from '../../bridge/generated-contracts'
import { FingerprintBlock } from '../../components/integrity/FingerprintBlock'
import { DecorativeIcon } from '../../design/icons'
import { StatusDimension } from './StatusDimension'

/**
 * Der EINZIGE Ort, an dem ein Objekt mit ungueltiger Verifikation erscheint.
 *
 * `view.rs` haelt solche Objekte aus `entries` heraus und legt sie allein in
 * `problems`; diese Flaeche zeigt sie als das, was sie sind — Objekthash,
 * Verifikationsurteil, Befundcode — und OEFFNET keines davon als Einsatz:
 * keine Schaltflaeche, keine Einsatzmaske, kein `article`. Ein Objekt, dessen
 * Signatur, Hash oder Grant nicht stimmt, hat keinen fachlichen Inhalt, den
 * die Flaeche zeigen duerfte (`design.md` §17.2).
 *
 * Die Liste ist die Liste der Bruecke: nichts wird hier gefiltert, sortiert
 * oder zusammengefasst.
 */
export function VerificationProblems({
  problems,
}: {
  readonly problems: readonly VerificationProblemView[]
}): ReactElement {
  return (
    <section aria-label="Prüfprobleme">
      <Space orientation="vertical" size="middle">
        {problems.length === 0 ? (
          <Space size="small">
            <DecorativeIcon name="verified" state="confirmed" />
            <Typography.Text>Der Bericht meldet kein Prüfproblem.</Typography.Text>
          </Space>
        ) : (
          <>
            <Space size="small">
              <DecorativeIcon name="warning" />
              <Typography.Text>
                {problems.length} Objekt{problems.length === 1 ? '' : 'e'} mit Befund. Keines davon
                wird als Einsatz geöffnet.
              </Typography.Text>
            </Space>
            <ul>
              {problems.map(problem => (
                <li key={problem.objectHash}>
                  <Space orientation="vertical" size="small">
                    <FingerprintBlock
                      entries={[{ label: 'Objekthash', value: problem.objectHash }]}
                    />
                    <StatusDimension
                      label="Verifikation"
                      value={problem.verification}
                      color="error"
                    />
                    {problem.detailCode === null ? null : (
                      <Typography.Text>
                        Befundcode: <Typography.Text code>{problem.detailCode}</Typography.Text>
                      </Typography.Text>
                    )}
                  </Space>
                </li>
              ))}
            </ul>
          </>
        )}
      </Space>
    </section>
  )
}

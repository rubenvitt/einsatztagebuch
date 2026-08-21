import { Button, Space, Typography } from 'antd'
import { useState } from 'react'
import type { ReactElement } from 'react'

import type { BundleExportView } from '../../bridge/generated-contracts'

/**
 * Der Ein-Datei-Buendelexport — PERMANENT und nicht hinter einer Bedingung.
 *
 * `showDirectoryPicker` fehlt in Safari und Firefox, also ist der Dateiweg der
 * EINZIGE universelle Weg in den Datei-Modus des Web-Readers. Eine Handhabe,
 * die nur unter einer Bedingung erscheint, waere fuer die Haelfte der Browser
 * gar keine.
 *
 * Was der Export NICHT tut: entschluesseln, Inhalt rendern, einen Verlauf
 * oeffnen. Er kopiert versiegelte Bytes, und die Oberflaeche erfaehrt Pfad,
 * Objektzahl und Byteumfang.
 */
export function ArchiveBundleExport({
  busy,
  onExport,
}: {
  readonly busy: boolean
  readonly onExport: () => Promise<BundleExportView>
}): ReactElement {
  const [report, setReport] = useState<BundleExportView | null>(null)
  const [failed, setFailed] = useState(false)
  return (
    <Space direction="vertical" size="small">
      <Button
        disabled={busy}
        onClick={() => {
          setFailed(false)
          void onExport().then(
            (result) => {
              setReport(result)
            },
            () => {
              setFailed(true)
            },
          )
        }}
      >
        Archiv-Bündel als Datei exportieren
      </Button>
      {report === null ? null : (
        <Typography.Text>
          {`${String(report.objectCount)} Objekte, ${String(report.byteCount)} Bytes: ${report.path}`}
        </Typography.Text>
      )}
      {failed ? (
        <Typography.Text>
          Der Export ist nicht zustande gekommen. Es sind keine Bytes geschrieben worden.
        </Typography.Text>
      ) : null}
    </Space>
  )
}

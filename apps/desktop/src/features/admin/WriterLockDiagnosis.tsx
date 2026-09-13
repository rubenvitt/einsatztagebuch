import { Alert, Button, Space, Typography } from 'antd'
import { useEffect, useRef, useState } from 'react'
import type { ReactElement } from 'react'
import type { LocalWriterLockDiagnosis } from '../../bridge/generated-contracts'
import { ContractViolation } from './contract-check'

const TEXT = {
  Missing: 'Keine Sperrdatei vorhanden.',
  AbandonedInert: 'Keine aktive Schreibsperre festgestellt.',
  LiveOwner: 'Das Archiv wird gerade von einem Writer gesperrt.',
  Unreadable: 'Der Sperrzustand konnte nicht sicher ermittelt werden.',
} satisfies Record<LocalWriterLockDiagnosis, string>

export function validateWriterLockDiagnosis(value: unknown): LocalWriterLockDiagnosis {
  if (typeof value !== 'string' || !Object.hasOwn(TEXT, value)) {
    throw new ContractViolation('Unbekannter Sperrzustand.')
  }
  return value as LocalWriterLockDiagnosis
}

export function WriterLockDiagnosis({ diagnose, busy }: {
  readonly diagnose: () => Promise<LocalWriterLockDiagnosis>
  readonly busy: boolean
}): ReactElement {
  const generation = useRef(0)
  const [pending, setPending] = useState(false)
  const [state, setState] = useState<LocalWriterLockDiagnosis | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    generation.current += 1
    setPending(false)
    setState(null)
    setFailed(false)
    return () => { generation.current += 1 }
  }, [diagnose])

  const inspect = async (): Promise<void> => {
    if (busy || pending) return
    const current = ++generation.current
    setPending(true)
    setState(null)
    setFailed(false)
    try {
      const result = validateWriterLockDiagnosis(await diagnose())
      if (generation.current === current) setState(result)
    } catch {
      if (generation.current === current) setFailed(true)
    } finally {
      if (generation.current === current) setPending(false)
    }
  }

  return <Space orientation="vertical">
    <Typography.Paragraph>
      Die Prüfung zeigt eine Momentaufnahme. Jede spätere Schreibaktion muss die Archiv-Sperre erneut erwerben.
    </Typography.Paragraph>
    <Button aria-label="Archiv-Sperre prüfen" disabled={busy || pending} loading={pending} onClick={() => { void inspect() }}>
      Archiv-Sperre prüfen
    </Button>
    {state !== null && <Typography.Paragraph role="status">{TEXT[state]}</Typography.Paragraph>}
    {failed && <Alert role="alert" type="warning" title="Die Archiv-Sperre konnte nicht geprüft werden." />}
  </Space>
}

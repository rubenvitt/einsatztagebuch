import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { DestructionStatus } from './DestructionStatus'

describe('DestructionStatus', () => {
  it.each([
    ['requested', 'beantragt'],
    ['inProgress', 'in Bearbeitung'],
    ['pendingBackupExpiry', 'wartet auf Backup-Frist'],
    ['completeManagedScope', 'im verwalteten Umfang abgeschlossen'],
    ['incompleteUnreachableReplica', 'bekannte Replik nicht erreichbar'],
  ] as const)('shows the exact state copy for %s', (state, label) => {
    render(<DestructionStatus state={state} />)
    expect(screen.getByRole('status', { name: 'Vernichtungsstatus' })).toHaveTextContent(label)
    expect(screen.getByText(/unbekannte Exporte.*Screenshots.*bereits entschlüsselte Inhalte/i)).toBeVisible()
  })

  it('does not turn a reached backup deadline into completion', () => {
    render(<DestructionStatus state="pendingBackupExpiry" />)
    expect(screen.getByRole('status')).toHaveTextContent('wartet auf Backup-Frist')
    expect(screen.queryByText('im verwalteten Umfang abgeschlossen')).not.toBeInTheDocument()
  })
})

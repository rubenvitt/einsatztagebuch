import { Space, Tag, Typography } from 'antd'
import type { ReactElement } from 'react'

import type { DestructionStateV1 } from '../../bridge/generated-contracts'

const STATUS_TEXT: Record<DestructionStateV1, string> = {
  requested: 'beantragt',
  inProgress: 'in Bearbeitung',
  pendingBackupExpiry: 'wartet auf Backup-Frist',
  completeManagedScope: 'im verwalteten Umfang abgeschlossen',
  incompleteUnreachableReplica: 'bekannte Replik nicht erreichbar',
}

const STATUS_COLOR: Record<DestructionStateV1, 'default' | 'processing' | 'warning' | 'success'> = {
  requested: 'default',
  inProgress: 'processing',
  pendingBackupExpiry: 'warning',
  completeManagedScope: 'success',
  incompleteUnreachableReplica: 'warning',
}

/** The signed process state comes from the host; elapsed time cannot complete it. */
export function DestructionStatus({ state }: { readonly state: DestructionStateV1 }): ReactElement {
  return (
    <Space direction="vertical" size="small">
      <div role="status" aria-label="Vernichtungsstatus">
        <Tag color={STATUS_COLOR[state]}>{STATUS_TEXT[state]}</Tag>
      </div>
      <Typography.Text type="secondary">
        Der Status gilt für den verwalteten Umfang. Unbekannte Exporte, Screenshots und bereits
        entschlüsselte Inhalte werden nicht zurückgerufen.
      </Typography.Text>
    </Space>
  )
}

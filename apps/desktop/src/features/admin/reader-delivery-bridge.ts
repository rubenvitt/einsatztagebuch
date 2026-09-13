import { invoke } from '@tauri-apps/api/core'
import { ContractViolation } from './contract-check'
import type { DestructionReaderDeliveryView } from '../../bridge/generated-contracts'

type NativeCall = (command: string, args?: Record<string, unknown>) => Promise<unknown>
export type ReaderDeliveryBridge = {
  export: (id: string, expectedPreflightHash: string, readerId: string) => Promise<DestructionReaderDeliveryView>
}
function reject(): never {
  throw new ContractViolation('Die Übergabedateien gehören nicht zur Auswahl oder überschreiten den Dateivertrag.')
}
function bytes(value: unknown, maximum: number): readonly number[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > maximum) return reject()
  for (const byte of value) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) return reject()
  }
  return value as number[]
}
/** Structural transport checks only. Each public original is verified again in Reader Rust. */
export function connectReaderDeliveryBridge(call: NativeCall = (command, args) => invoke<unknown>(command, args)): ReaderDeliveryBridge {
  return {
    export: async (destructionId, expectedPreflightHash, readerId) => {
      const raw = await call('destruction_export_reader_delivery', { destructionId, expectedPreflightHash, readerId })
      if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return reject()
      const value = raw as Record<string, unknown>
      if (value.destructionId !== destructionId || value.jobHash !== expectedPreflightHash || value.readerId !== readerId) return reject()
      return {
        destructionId, jobHash: expectedPreflightHash, readerId,
        exactAuthorization: bytes(value.exactAuthorization, 4 * 1024 * 1024),
        exactInitiatingEvent: bytes(value.exactInitiatingEvent, 4 * 1024 * 1024),
        exactJobUpload: bytes(value.exactJobUpload, 64 * 1024 * 1024),
      }
    },
  }
}

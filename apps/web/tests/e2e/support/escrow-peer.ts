// Der native Gegenpart des Escrow-Browserzeugen: das Rust-Beispiel
// `tests/ea-system-tests/examples/reader_key_escrow_browser_peer.rs`.
//
// Es wird NICHT hier gebaut, sondern vorher mit
// `cargo build --locked -p ea-system-tests --example reader_key_escrow_browser_peer`;
// der Pfad folgt `$CARGO_TARGET_DIR` (die Worktree-Umgebung setzt ihn) und
// sonst dem Standardziel. Fehlt das Binary, scheitert der Lauf LAUT — ein
// `skip` liesse den Browserzeugen still leerlaufen.
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repository = path.resolve(here, '../../../../..')

export function peerBinary(): string {
  const target = process.env['CARGO_TARGET_DIR'] ?? path.join(repository, 'target')
  const binary = path.join(target, 'debug', 'examples', 'reader_key_escrow_browser_peer')
  if (!existsSync(binary)) {
    throw new Error(
      `Der Escrow-Peer fehlt unter ${binary}. Vorher bauen: ` +
        'cargo build --locked -p ea-system-tests --example reader_key_escrow_browser_peer',
    )
  }
  return binary
}

/** Ruft den Peer und gibt seine JSON-Antwort zurueck. */
export function peer<T>(args: readonly string[]): T {
  const output = execFileSync(peerBinary(), [...args], { encoding: 'utf8' })
  return JSON.parse(output) as T
}

/** Alle Dateien eines Ordners als absolute Pfade. */
export function filesIn(directory: string): string[] {
  return readdirSync(directory)
    .sort()
    .map(name => path.join(directory, name))
}

/** Der Freigabekontext, wie die Anwendung ihn global erwartet. */
export type PeerReleaseContext = {
  readonly organizationId: string
  readonly subjectId: string
  readonly pinnedAnchor: string
}

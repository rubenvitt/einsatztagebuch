// Local view lifetime only. This signal grants no deletion or trust authority.
const listeners = new Set<() => void>()
export function invalidateReaderViews(): void {
  for (const listener of listeners) listener()
}
export function onReaderViewsInvalidated(listener: () => void): () => void {
  listeners.add(listener)
  return () => { listeners.delete(listener) }
}

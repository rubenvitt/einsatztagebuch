// Die Platzhalterdeklaration fuer die VITE-ANFRAGE am Modulpfad.
//
// `apps/web/src/bridge/wasm-runtime.test.ts` importiert das Bruecken-Modul ein
// zweites Mal mit dem Suffix `?no-webcrypto`, um eine FRISCHE Instanz zu
// erzwingen — der Modulzwischenspeicher schluesselt ueber den ganzen
// Bezeichner, und nur so findet die Instanziierung ohne Web Crypto statt.
// TypeScript kennt diese Form nicht und meldet sonst TS2307.
//
// Die Deklaration nennt genau die zwei Namen, die der Zeuge benutzt, und
// erfindet keine Flaeche: die vollstaendige Gestalt steht in
// `pkg/ea_reader_wasm.d.ts` und wird von dort gelesen, nicht hier wiederholt.
declare module '*?no-webcrypto' {
  export const readerRuntimeWitness: () => string
  const init: (options: { module_or_path: BufferSource }) => Promise<unknown>
  export default init
}

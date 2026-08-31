// Negativkontrolle zu Element 2.
//
// Nimmt `globalThis.crypto` weg und ruft dann denselben wasm-bindgen-Export auf.
// Wenn die Entropie wirklich aus der JS-Umgebung kommt, MUSS getrandom hier
// scheitern. Tut es das nicht, waere die Entropie im Modul eingebacken und der
// Nachweis wertlos.
//
// Erfolg dieses Skripts = getrandom meldet einen Fehler. Exit 0 bei Fehlschlag
// von getrandom, Exit 1 wenn getrandom trotzdem Bytes liefert.

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgPath = path.resolve(here, "..", "pkg", "ea_wasm_runtime_proof.js");
const require = createRequire(import.meta.url);

Object.defineProperty(globalThis, "crypto", { value: undefined, configurable: true });

const wasm = require(pkgPath);
const report = JSON.parse(wasm.run_runtime_proof());

console.log(`ok=${report.ok}`);
console.log(`errors=${report.errors}`);
console.log(`getrandom=${JSON.stringify(report.getrandom)}`);

if (report.getrandom === null && /Web Crypto API is unavailable/.test(report.errors)) {
  console.log("NEGATIVE CONTROL HELD: without globalThis.crypto, getrandom fails.");
  process.exit(0);
}
console.error("NEGATIVE CONTROL BROKEN: getrandom produced bytes without globalThis.crypto.");
process.exit(1);

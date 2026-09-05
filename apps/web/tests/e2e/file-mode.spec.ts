// Der BROWSERZEUGE des Datei-Modus nach `web-reader-design.md` §5.2.
//
// # Was dieser Lauf NICHT bezeugen kann, und das gehoert hierher
//
// Die Eigenschaft, die den universellen Weg ueberhaupt noetig macht, ist die
// ABWESENHEIT von `showDirectoryPicker` in Safari und Firefox — und dieser
// Zeuge laeuft ausschliesslich im Projekt `chromium`, wo die Faehigkeit DA
// ist (die Anti-Leerlauf-Zeile unten misst genau das). Die Abwesenheit haengt
// deshalb an zwei anderen Zeugen: an der Faehigkeitsabfrage in
// `src/features/file-mode/OpenArchivePanel.test.tsx`, die den Wirt ohne
// `showDirectoryPicker` doubelt, und an `browser-matrix.spec.ts`, das dieselbe
// Route in allen drei Engines faehrt und die Faehigkeit je Engine als
// gemessene Tabelle traegt (gemessen: Firefox 153 und WebKit 26.5 liefern
// `false`, dieser Lauf fiele dort an seiner Anti-Leerlauf-Zeile).
//
// In diesem Task entsteht KEIN Playwright-Geruest, sondern eine dritte Spec
// darin. Gemessen wird, was nur ein echter Browser messen kann: dass die Route
// `/datei` in der GEBAUTEN Anwendung montiert, und dass der universelle Weg
// dort ein echtes `<input type="file">` ist statt eines Aufrufs von
// `showOpenFilePicker` — die fehlt in denselben zwei Engines wie
// `showDirectoryPicker`, und eine Flaeche, die auf sie baute, waere genau so
// unbenutzbar wie eine ohne universellen Weg.
//
// `web:e2e` bleibt AUSSERHALB von `verify:quick`, aus dem Grund, den
// `verify_quick_commands()` in `tools/xtask/src/main.rs` bereits notiert:
// Playwright verlangt installierte Engine-Baus und der
// wasm-bindgen-Testlaeufer einen chromedriver, beides waere eine neue
// Containervoraussetzung fuer JEDEN Schnelllauf. Die benannte Klammer ist
// `browsers up` … `browsers down`.
import { expect, test } from '@playwright/test'

test.skip(({ browserName }) => browserName !== 'chromium')

test('mounts the file mode route and offers the universal file input in a real engine', async ({
  page,
}) => {
  await page.goto('/datei')

  const universal = page.getByLabel('Archivdatei öffnen')
  await expect(universal).toBeVisible()
  await expect(universal).toBeEnabled()
  // Die EIGENSCHAFT und nicht das Aussehen: ein `<input type="file">` braucht
  // keine Dateisystem-API und traegt deshalb in jeder Engine.
  await expect(universal).toHaveAttribute('type', 'file')

  // ANTI-LEERLAUF: dieser Browser HAT die Faehigkeit. Ohne diese Zeile bliebe
  // offen, ob die Zusicherung darunter die Faehigkeitsabfrage misst oder eine
  // Schaltflaeche, die immer da ist.
  expect(await page.evaluate(() => 'showDirectoryPicker' in window)).toBe(true)
  await expect(page.getByRole('button', { name: 'Archivordner verbinden' })).toBeVisible()

  // `nicht server-bestaetigt` ist der REGELFALL und kein Mangel — und vor dem
  // ersten Oeffnen sagt die Flaeche ueber einen Bestand ueberhaupt nichts.
  // Alarmiert wird hier nie.
  await expect(page.getByRole('alert')).toHaveCount(0)
})

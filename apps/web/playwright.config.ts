import { devices } from '@playwright/test'
import type { PlaywrightTestConfig } from '@playwright/test'

// Die Vorschau des GEBAUTEN Buendels. `vite preview` liefert `dist/`, also
// genau die Bytes, die spaeter ausgeliefert werden — nicht den Dev-Server mit
// seiner Modultransformation zur Laufzeit. Das ist hier mehr als eine
// Formsache: `apps/web/index.html` traegt die Content-Security-Policy, und nur
// die gebaute Fassung zeigt, ob das wasm-Modul und der OPFS-Worker unter ihr
// ueberhaupt laden. `vite preview` BAUT nicht, deshalb steht `vite build` im
// selben Kommando davor: ohne den Vorlauf bricht der `webServer` mit
// 'The directory "dist" does not exist' ab, und zwar VOR der Testsuche.
//
// EIN ANDERER PORT als die 4173 des Desktops, damit beide Suiten nebeneinander
// laufen koennen; `--strictPort` macht eine Kollision zu einem lauten Abbruch
// statt zu einem stillen Ausweichen auf 4175, auf dem `url` dann nie antwortet.
const PREVIEW_PORT = 4174

// AUF DIE IPv4-SCHLEIFE GEPINNT, in beiden Haelften — dieselbe Messung wie in
// `apps/desktop/playwright.config.ts`: `vite preview` bindet ohne `--host` an
// den Namen `localhost`, und Node loest den auf diesem Rechner zu `[::1]` auf.
// Ein `http://127.0.0.1:4174` waere dann NICHT erreichbar, und der
// Bereitschaftstest von Playwright laeuft gegen `url`.
const PREVIEW_ORIGIN = `http://127.0.0.1:${PREVIEW_PORT}`

/**
 * Dieselbe Vorschau unter ihrem NAMEN, und der Grund ist gemessen und nicht
 * gefolgert.
 *
 * WebAuthn leitet die Relying-Party-Kennung aus dem Host der aufrufenden
 * Herkunft ab, und eine IP-Adresse ist dort KEIN gueltiger Wert: derselbe
 * `navigator.credentials.create`, der unter `http://localhost:4174` durchlaeuft,
 * faellt unter `http://127.0.0.1:4174` mit
 * `SecurityError: This is an invalid domain.` — beide Laeufe stehen im Bericht
 * dieser Aufgabe. Ein Browserzeuge, der eine Zeremonie fuehrt, muss die Seite
 * deshalb ueber diesen Namen aufrufen und nicht ueber `baseURL`.
 *
 * `baseURL` und `webServer.url` bleiben trotzdem auf der IPv4-SCHLEIFE, und das
 * ist kein Widerspruch: Playwrights Bereitschaftstest laeuft gegen `url`, und
 * `vite preview` bindet mit `--host 127.0.0.1` genau dort. Der Name `localhost`
 * erreicht dieselbe Bindung — Chromium loest ihn selbst auf und faellt auf
 * `127.0.0.1` zurueck, wenn `[::1]` nicht antwortet (gemessen: die Seite laedt).
 * Getrennt bleiben damit ZWEI Dinge, die nur zufaellig dieselbe Maschine
 * meinen: die Adresse, unter der Playwright den Server sucht, und die Herkunft,
 * unter der eine Zeremonie eine gueltige Relying Party hat.
 */
export const WEBAUTHN_PREVIEW_ORIGIN = `http://localhost:${PREVIEW_PORT}`

// `satisfies` statt `defineConfig(...)`: die Signatur von `defineConfig` gibt
// `PlaywrightTestConfig` zurueck, und dort ist `webServer` die Vereinigung
// `TestConfigWebServer | TestConfigWebServer[]`. `config.webServer?.command`
// aus `src/e2e-config.test.ts` faellt dagegen mit TS2339. `satisfies` prueft
// dieselbe Konfigurationsform und behaelt den Literaltyp, also bleibt die
// Zusicherung des Zeugen lesbar UND typisierbar. Playwright liest den
// Default-Export.
export default {
  // RELATIV ZUM PAKET. `<repo>/tests/` ist dem Rust-Mitglied
  // `tests/ea-system-tests` vorbehalten, deshalb liegt die E2E-Suite unter
  // `apps/web/tests/e2e` und
  // `pnpm --dir apps/web exec playwright test tests/e2e/<spec>` loest auf.
  testDir: 'tests/e2e',
  webServer: {
    command: `pnpm exec vite build && pnpm exec vite preview --host 127.0.0.1 --port ${PREVIEW_PORT} --strictPort`,
    url: PREVIEW_ORIGIN,
    reuseExistingServer: false,
    // Der Vorlauf baut jetzt mit; die Vorgabe von 60 s deckt einen kalten
    // Vite-Bau samt Ant Design nicht zuverlaessig.
    timeout: 180_000,
  },
  use: {
    baseURL: PREVIEW_ORIGIN,
    // AUSDRUECKLICH FALSCH UND NICHT VERGESSEN. `offline: true` auf
    // Kontextebene setzt Playwright in Chromium ueber
    // `Network.emulateNetworkConditions`, und das trifft den GESAMTEN
    // Netzstapel des Kontexts EINSCHLIESSLICH `127.0.0.1` — die Anwendung
    // selbst laedt dann nie (gemessen am Desktop-Pendant, dessen Kopf die
    // Messung ausschreibt). Wo eine spaetere Aufgabe den Netzzugang abschalten
    // will, tut sie es ueber ein Anfragepraedikat und nicht hier.
    offline: false,
  },
  // DREI Projekte — die Engine-Achse der Browsermatrix nach
  // `web-reader-design.md` §11.4 (Engine, Version, Plattform statt
  // Architektur, Installerformat, Key-Provider). `src/e2e-config.test.ts`
  // pinnt die drei Namen in dieser Reihenfolge, damit ein viertes Projekt oder
  // ein fehlendes eine bewusste Aenderung bleibt und kein Nebeneffekt.
  //
  // `webkit` ist Playwrights WebKit-Bau und NICHT Safari; der Gate-Bericht
  // nennt den Unterschied, weil der Lauf sonst als Safari-Nachweis gelesen
  // wuerde. Was je Engine ueberhaupt laeuft, entscheidet jede Spec selbst
  // ueber `test.skip(({ browserName }) => ...)`: `enrollment.spec.ts` bleibt
  // auf `chromium`, weil `WebAuthn.addVirtualAuthenticator` eine CDP-Methode
  // ist, die Firefox und WebKit nicht anbieten.
  //
  // Der Engine-Bau von WebKit laeuft NUR auf einem Wirt mit seinen
  // Systembibliotheken (gemessen auf dem Entwicklungsrechner:
  // `MiniBrowser: error while loading shared libraries: libevent-2.1.so.7`).
  // Deshalb kann das Projekt `webkit` ueber `EA_WEBKIT_WS_ENDPOINT` an einen
  // Playwright-Server angebunden werden, der die Engine in dem Abbild
  // faehrt, auf dem auch `ops/compose/browsers.yaml` baut — gemessen:
  //   docker run --rm --network host mcr.microsoft.com/playwright:v1.62.1-noble \
  //     npx -y playwright@1.62.1 run-server --port 3001 --host 127.0.0.1
  //   EA_WEBKIT_WS_ENDPOINT=ws://127.0.0.1:3001/ pnpm --dir apps/web exec playwright test --project=webkit
  // `--network host` ist dieselbe Messung wie im Browserdienst: der WebKit im
  // Container muss `vite preview` auf `127.0.0.1:4174` des WIRTS erreichen.
  // Ohne die Variable startet das Projekt die Engine lokal — die Form, die CI
  // und ein Wirt mit Systemabhaengigkeiten fahren.
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    {
      name: 'webkit',
      use: {
        ...devices['Desktop Safari'],
        ...(process.env['EA_WEBKIT_WS_ENDPOINT'] === undefined
          ? {}
          : { connectOptions: { wsEndpoint: process.env['EA_WEBKIT_WS_ENDPOINT'] } }),
      },
    },
  ],
} satisfies PlaywrightTestConfig

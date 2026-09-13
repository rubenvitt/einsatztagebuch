// Private fixture protocol: one readiness line, one input filename on stdin,
// one completion line. No fixture payload, PRF, Vault or browser trace logging.
import { createRequire } from 'node:module'
import { readFile, writeFile, cp } from 'node:fs/promises'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createInterface } from 'node:readline'
const [webRoot, privateRoot] = process.argv.slice(2)
const require = createRequire(resolve(webRoot, 'package.json'))
const { createServer } = await import(require.resolve('vite'))
const { chromium } = require('@playwright/test')
const here = dirname(fileURLToPath(import.meta.url))
const server = await createServer({ configFile: false, root: webRoot, logLevel: 'silent',
  server: { host: '127.0.0.1', port: 0, fs: { allow: [webRoot, here] } },
  plugins: [{ name: 'native-reader-fixture-page', configureServer(server) {
    server.middlewares.use('/__native_reader_harness', (_request, response) => {
      response.setHeader('Content-Type', 'text/html')
      response.end(`<html><script type="module" src="/@fs/${here}/reader_opfs.browser.js"></script></html>`)
    })
  } }],
})
let context
try {
  await server.listen()
  const address = server.httpServer.address()
  const origin = `http://127.0.0.1:${address.port}/__native_reader_harness`
  const profile = resolve(privateRoot, 'reader-profile')
  const open = async path => {
    context = await chromium.launchPersistentContext(path, { headless: true })
    const page = context.pages()[0] ?? await context.newPage()
    await page.goto(origin)
    await page.waitForFunction(() => window.readerHarness !== undefined)
    await page.evaluate(() => window.readerHarness.ready())
    return page
  }
  let page = await open(profile)
  process.stdout.write('READY\n')
  const lines = createInterface({ input: process.stdin })
  const inputPath = await new Promise(resolve => lines.once('line', resolve))
  lines.close()
  const input = JSON.parse(await readFile(inputPath, 'utf8'))
  const result = await page.evaluate(input => window.readerHarness.apply(input), input)
  await context.close(); context = undefined
  page = await open(profile)
  result.reopenedIdentical = await page.evaluate(({ input, etb }) => window.readerHarness.historical(input, etb), { input, etb: result.etb })
  await context.close(); context = undefined
  // Copy only this closed test profile. Reappearance never mutates or repairs
  // the successful profile, whose missing cache remains independently true.
  const negativeProfile = resolve(privateRoot, 'reader-reappeared-profile')
  await cp(profile, negativeProfile, { recursive: true })
  page = await open(negativeProfile)
  result.reappearance = await page.evaluate(({ input, etb }) => window.readerHarness.historical(input, etb, true), { input, etb: result.etb })
  await writeFile(resolve(privateRoot, 'reader-attestation.etb'), Uint8Array.from(result.etb), { mode: 0o600 })
  delete result.etb
  await writeFile(resolve(privateRoot, 'reader-result.json'), JSON.stringify(result), { mode: 0o600 })
  process.stdout.write('COMPLETE\n')
} catch (error) {
  // Product error codes and harness assertion labels only, never input data.
  process.stderr.write(`native-reader-harness: ${String(error.message).slice(0, 1200)}\n`)
  process.exitCode = 1
} finally {
  await context?.close()
  await server.close()
}

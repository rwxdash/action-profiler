import { fileURLToPath } from 'node:url'
import path from 'node:path'
import fs from 'node:fs'
import * as core from '@actions/core'
import * as exec from '@actions/exec'
import { DefaultArtifactClient } from '@actions/artifact'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const STATE_PID = 'PROFILER_PID'
const STATE_OUTPUT = 'PROFILER_OUTPUT'
const ARTIFACT_NAME = 'action-profiler-report'

export async function run(): Promise<void> {
  try {
    const profilerPid = core.getState(STATE_PID)
    const outputPath = core.getState(STATE_OUTPUT)

    if (!profilerPid) {
      core.warning('Profiler PID not found in state — was it started?')
      return
    }

    // Stop the profiler gracefully
    core.info(`Sending SIGINT to profiler (PID ${profilerPid})...`)
    try {
      await exec.exec('sudo', ['kill', '-s', 'INT', profilerPid])
    } catch {
      core.warning(
        `Failed to send SIGINT to PID ${profilerPid} — it may have already exited`
      )
    }

    await waitForExit(profilerPid, 10_000)

    // Read JSONL output
    if (!fs.existsSync(outputPath)) {
      core.warning(`Profiler output not found at ${outputPath}`)
      return
    }

    const jsonlSize = fs.statSync(outputPath).size
    const lineCount = fs
      .readFileSync(outputPath, 'utf-8')
      .split('\n')
      .filter(l => l.trim()).length
    core.info(`Profiler output: ${jsonlSize} bytes (${lineCount} events)`)

    // Build artifact directory: viewer + WASM + JSONL
    const artifactDir = path.join(
      process.env.RUNNER_TEMP || '/tmp',
      'profiler-artifact'
    )
    fs.mkdirSync(artifactDir, { recursive: true })
    buildArtifact(outputPath, artifactDir)

    // Upload artifact
    const files = collectFiles(artifactDir)
    core.info(`Uploading ${files.length} files as "${ARTIFACT_NAME}"...`)

    const client = new DefaultArtifactClient()
    const { id, size } = await client.uploadArtifact(
      ARTIFACT_NAME,
      files,
      artifactDir,
      { compressionLevel: 6, retentionDays: 3 }
    )

    if (id) {
      const server = process.env.GITHUB_SERVER_URL || 'https://github.com'
      const repo = process.env.GITHUB_REPOSITORY || ''
      const runId = process.env.GITHUB_RUN_ID || ''
      const artifactUrl = `${server}/${repo}/actions/runs/${runId}/artifacts/${id}`

      core.info(`Artifact uploaded (${size} bytes): ${artifactUrl}`)
      core.setOutput('artifact-id', id.toString())
      core.setOutput('artifact-url', artifactUrl)
    }

    core.info('Action profiler post phase complete.')
  } catch (error) {
    if (error instanceof Error) core.setFailed(error.message)
  }
}

function buildArtifact(jsonlPath: string, outputDir: string): void {
  const binOut = path.resolve(__dirname, '../../profiler/bin/out')

  // Read all sources
  let html = fs.readFileSync(path.join(binOut, 'index.html'), 'utf-8')
  const jsGlue = fs.readFileSync(
    path.join(binOut, 'pkg/profiler_viewer.js'),
    'utf-8'
  )
  const wasmBase64 = fs
    .readFileSync(path.join(binOut, 'pkg/profiler_viewer_bg.wasm'))
    .toString('base64')
  const jsonlData = fs.readFileSync(jsonlPath, 'utf-8')

  // Strip export keywords from JS glue (inlined into the module script)
  const jsInline = jsGlue
    .replace(/^export function /gm, 'function ')
    .replace(/^export \{[^}]*\};?\s*$/gm, '')

  // Replace the import line with inlined JS glue
  html = html.replace(
    "import init, { process_jsonl } from './pkg/profiler_viewer.js';",
    `// ── Inlined WASM viewer (self-contained) ──\n${jsInline}\n        const init = __wbg_init;`
  )

  // Replace `await init()` with base64 WASM loading
  html = html.replace(
    'await init();',
    [
      'const __wasmB64 = "' + wasmBase64 + '";',
      '        const __wasmBin = Uint8Array.from(atob(__wasmB64), c => c.charCodeAt(0));',
      '        await init(__wasmBin.buffer);'
    ].join('\n')
  )

  // Replace the fetch('profiler-events.jsonl') block with inline JSONL data
  html = html.replace(
    /fetch\('profiler-events\.jsonl'\)\s*\n\s*\.then\(r => r\.text\(\)\)\s*\n\s*\.then\(text => \{ if \(text\.trim\(\)\) loadJsonl\(text\); \}\)\s*\n\s*\.catch\(\(\) => \{ \}\);/,
    `loadJsonl(${JSON.stringify(jsonlData)});`
  )

  fs.writeFileSync(path.join(outputDir, 'index.html'), html)

  // Include raw JSONL for offline analysis
  fs.copyFileSync(jsonlPath, path.join(outputDir, 'profiler-events.jsonl'))
}

function collectFiles(dir: string): string[] {
  const files: string[] = []
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      files.push(...collectFiles(full))
    } else {
      files.push(full)
    }
  }
  return files
}

async function waitForExit(pid: string, timeoutMs: number): Promise<void> {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    try {
      await exec.exec('sudo', ['kill', '-0', pid], { silent: true })
      await new Promise(r => setTimeout(r, 300))
    } catch {
      return // process exited
    }
  }
  core.warning(`Profiler PID ${pid} did not exit within ${timeoutMs}ms`)
}

run()

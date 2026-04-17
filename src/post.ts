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
      core.warning('Profiler PID not found in state - was it started?')
      return
    }

    // Stop the profiler gracefully
    core.info(`Sending SIGINT to profiler (PID ${profilerPid})...`)
    try {
      await exec.exec('sudo', ['kill', '-s', 'INT', profilerPid])
    } catch {
      core.warning(
        `Failed to send SIGINT to PID ${profilerPid} - it may have already exited`
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
      .filter((l) => l.trim()).length
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
      {
        compressionLevel: 6,
        retentionDays: parseInt(
          core.getInput('artifact_retention_days') || '3',
          10
        )
      }
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
  const echartsJs = fs.readFileSync(
    path.join(binOut, 'echarts.min.js'),
    'utf-8'
  )
  const jsGlue = fs.readFileSync(
    path.join(binOut, 'pkg/profiler_viewer.js'),
    'utf-8'
  )
  const wasmBase64 = fs
    .readFileSync(path.join(binOut, 'pkg/profiler_viewer_bg.wasm'))
    .toString('base64')
  const jsonlData = fs.readFileSync(jsonlPath, 'utf-8')

  // Inline ECharts (source HTML references ./echarts.min.js for local dev;
  // we inline it here so the artifact is self-contained and opens from file://)
  html = replaceAnchor(html, 'ECHARTS', `<script>\n${echartsJs}\n</script>`)

  // Strip export keywords from JS glue (inlined into the module script)
  const jsInline = jsGlue
    .replace(/^export function /gm, 'function ')
    .replace(/^export \{[^}]*\};?\s*$/gm, '')

  // Replace the three AP:* anchored blocks in the source HTML. See the
  // `<<< AP:NAME` ... `>>> AP:NAME` markers in profiler/tests/index.html.
  // Anchor comments survive any code formatter so the artifact build is not
  // coupled to whitespace or semicolon decisions.
  html = replaceAnchor(
    html,
    'WASM_IMPORT',
    `// ── Inlined WASM viewer (self-contained) ──\n${jsInline}\n        const init = __wbg_init;`
  )
  html = replaceAnchor(
    html,
    'WASM_INIT',
    [
      'const __wasmB64 = "' + wasmBase64 + '";',
      '        const __wasmBin = Uint8Array.from(atob(__wasmB64), c => c.charCodeAt(0));',
      '        await init({ module_or_path: __wasmBin.buffer });'
    ].join('\n')
  )
  html = replaceAnchor(
    html,
    'JSONL_AUTOLOAD',
    `loadJsonl(${JSON.stringify(jsonlData)});`
  )

  fs.writeFileSync(path.join(outputDir, 'index.html'), html)

  // Include raw JSONL for offline analysis
  fs.copyFileSync(jsonlPath, path.join(outputDir, 'profiler-events.jsonl'))
}

// Replace the region between `<<< AP:<name>` and `>>> AP:<name>` anchor
// comments with `replacement`. The anchor lines themselves are removed too.
// Throws if either anchor is missing or out of order - surfaces build problems
// in CI instead of shipping a broken artifact.
function replaceAnchor(
  html: string,
  name: string,
  replacement: string
): string {
  const start = html.indexOf(`<<< AP:${name}`)
  const end = html.indexOf(`>>> AP:${name}`)
  if (start < 0 || end < 0 || end < start) {
    throw new Error(
      `buildArtifact: anchor AP:${name} not found (or malformed) in source HTML`
    )
  }
  // Expand the cut to the full lines containing the anchor comments so we
  // don't leave a dangling `//` or trailing newline in the artifact.
  const lineStart = html.lastIndexOf('\n', start) + 1
  const endMarkerEnd = end + `>>> AP:${name}`.length
  const lineEnd = html.indexOf('\n', endMarkerEnd)
  return (
    html.slice(0, lineStart) +
    replacement +
    (lineEnd < 0 ? '' : html.slice(lineEnd))
  )
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
      await new Promise((r) => setTimeout(r, 300))
    } catch {
      return // process exited
    }
  }
  core.warning(`Profiler PID ${pid} did not exit within ${timeoutMs}ms`)
}

run()

import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import fs from 'node:fs'
import * as core from '@actions/core'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const STATE_PID = 'PROFILER_PID'
const STATE_OUTPUT = 'PROFILER_OUTPUT'

export async function run(): Promise<void> {
  try {
    if (process.platform !== 'linux') {
      core.warning(
        `action-profiler requires Linux (eBPF). Skipping on ${process.platform}.`
      )
      return
    }

    // Check if sudo is available (eBPF requires root/CAP_BPF)
    try {
      const { execSync } = await import('node:child_process')
      execSync('sudo -n true 2>/dev/null')
    } catch {
      core.warning(
        'action-profiler requires sudo (for eBPF). Skipping - no sudo access.'
      )
      return
    }

    const profilerBin = path.resolve(__dirname, '../../profiler/bin/profiler')

    if (!fs.existsSync(profilerBin)) {
      core.warning(
        'No profiler binary found. Run scripts/build.sh to build it. ' +
          'See https://github.com/rwxdash/action-profiler for details.'
      )
      return
    }

    fs.chmodSync(profilerBin, 0o755)

    const tmpDir = process.env.RUNNER_TEMP || '/tmp'
    const outputPath = path.join(tmpDir, 'profiler-events.jsonl')

    const metricFrequency = core.getInput('metric_frequency') || '5'
    const procTraceSysEnable =
      core.getInput('proc_trace_sys_enable') === 'true'
    const ignoreProcesses = core.getInput('ignore_processes')
    const ignorePatterns = core.getInput('ignore_patterns')
    const enableOom = core.getInput('enable_oom') !== 'false'
    const enableBlockIo = core.getInput('enable_block_io') !== 'false'
    const enableSchedLatency = core.getInput('enable_sched_latency') !== 'false'
    const schedThreshold = core.getInput('sched_latency_threshold_ms') || '5'

    const args: string[] = [
      profilerBin,
      '--output',
      outputPath,
      '--metric-frequency',
      metricFrequency,
      '--sched-latency-threshold-ms',
      schedThreshold
    ]

    if (procTraceSysEnable) {
      args.push('--no-default-ignore')
    }
    if (ignoreProcesses) {
      args.push('--ignore', ignoreProcesses)
    }
    if (ignorePatterns) {
      args.push('--ignore-pattern', ignorePatterns)
    }
    if (!enableOom) {
      args.push('--no-oom')
    }
    if (!enableBlockIo) {
      args.push('--no-block-io')
    }
    if (!enableSchedLatency) {
      args.push('--no-sched-latency')
    }

    core.info(`Spawning profiler: sudo ${args.join(' ')}`)

    const child = spawn('sudo', args, {
      detached: true,
      stdio: 'ignore'
    })

    child.unref()

    if (!child.pid) {
      core.setFailed('Failed to start profiler - no PID returned')
      return
    }

    core.saveState(STATE_PID, child.pid.toString())
    core.saveState(STATE_OUTPUT, outputPath)

    core.info(`Profiler started (PID ${child.pid}), output: ${outputPath}`)
  } catch (error) {
    if (error instanceof Error) core.setFailed(error.message)
  }
}


run()

import {collectInstalled} from '../../security/installed.js'
import {classifyTyposquat} from '../../security/typosquat.js'
import {makeFinding} from '../findings.js'

// Offline core dependency hygiene only. Vulnerability/advisory matching and
// installed-code malware heuristics are owned by the separate Online package.
export function runDependencyIntegrityChecks(repoPath, {packageScopes = []} = {}) {
  const findings = []
  let installedCount = 0
  try {
    const inventory = collectInstalled(repoPath)
    installedCount = inventory.installed.length
    const directNames = new Set(packageScopes.flatMap((scope) => Object.keys({
      ...(scope.pkg?.dependencies || {}),
      ...(scope.pkg?.devDependencies || {}),
    })))
    for (const name of directNames) {
      const candidate = classifyTyposquat(name)
      if (!candidate) continue
      findings.push(makeFinding({
        category: 'structure',
        rule: 'typosquat',
        severity: 'medium',
        confidence: 'low',
        title: `Possible dependency name confusion: ${name} (looks like "${candidate.nearest}")`,
        detail: `Direct dependency "${name}" is edit-distance ${candidate.distance} from "${candidate.nearest}". Confirm the declaration is intentional. This is name-confusion evidence, not a vulnerability or malware verdict.`,
        package: name,
        source: 'internal',
        fixHint: `verify "${name}" is the intended package rather than a typo of "${candidate.nearest}"`,
      }))
    }
    for (const item of inventory.drift.slice(0, 20)) {
      findings.push(makeFinding({
        category: 'structure',
        rule: 'lockfile-drift',
        severity: 'low',
        confidence: 'medium',
        title: `Lockfile drift: ${item.name} (locked ${item.locked}, installed ${item.installed})`,
        detail: 'The installed version differs from every version recorded for this package in the lockfile. This usually means a stale or manually changed install; reinstall from the lockfile.',
        package: item.name,
        version: item.installed,
        source: 'internal',
        fixHint: 'recreate installed dependencies from the lockfile',
      }))
    }
  } catch (error) {
    return {
      findings,
      installedCount,
      status: 'PARTIAL',
      detail: `Installed dependency inventory failed: ${error instanceof Error ? error.message : String(error)}`,
    }
  }
  return {
    findings,
    installedCount,
    status: 'COMPLETE',
    detail: `Inventoried ${installedCount} pinned or installed package coordinate(s) for lockfile drift and direct-name confusion.`,
  }
}

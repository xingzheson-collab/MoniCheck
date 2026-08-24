const content = document.querySelector('#content')
const title = document.querySelector('#title')
let report = {}
let status = {}
let audit = {}

async function load() {
  try {
    ;[report, status, audit] = await Promise.all([
      fetch('/api/v1/local/report').then(readJSON),
      fetch('/api/v1/local/status').then(readJSON),
      fetch('/api/v1/local/agent-audit').then(readJSON),
    ])
    document.querySelector('#activation').hidden = !(report.resource_count > 0)
    render(active())
  } catch (_error) {
    content.innerHTML = '<div class="panel">Local report could not be loaded.</div>'
  }
}

function readJSON(response) {
  if (!response.ok) throw new Error(`request failed: ${response.status}`)
  return response.json()
}

function active() {
  return document.querySelector('nav .active').dataset.view
}

function escapeHTML(item) {
  return String(item ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;')
}

function coverageMetric() {
  const coverage = report.coverage_percent || 0
  const complete = report.coverage_evidence_completeness_percent || 0
  const partial = (report.coverage_evidence_state || 'UNKNOWN') !== 'COMPLETE'
  return partial
    ? `<div class="metric evidence"><span>Evidence completeness</span><strong>${complete}%</strong><small>Evaluable coverage: ${coverage}%</small></div>`
    : `<div class="metric"><span>Coverage</span><strong>${coverage}%</strong><small>Complete evidence</small></div>`
}

function metrics() {
  return `<div class="metrics"><div class="metric"><span>Resources</span><strong>${report.resource_count || 0}</strong></div><div class="metric"><span>Open findings</span><strong>${report.open_finding_count || 0}</strong></div><div class="metric"><span>Critical</span><strong class="critical">${report.critical_count || 0}</strong></div>${coverageMetric()}</div>`
}

function value(item) {
  if (item === null || item === undefined) return ''
  if (typeof item === 'object') return item.name || item.id || ''
  return item
}

function table(rows, columns) {
  if (!rows.length) return '<div class="panel empty">No matching items in this audit.</div>'
  return `<div class="panel table-panel"><table><thead><tr>${columns.map((column) => `<th>${escapeHTML(column[0])}</th>`).join('')}</tr></thead><tbody>${rows.map((row) => `<tr>${columns.map((column) => `<td>${escapeHTML(value(row[column[1]]))}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`
}

function severityClass(severity) {
  return String(severity || '').toLowerCase()
}

function actionGroups() {
  const groups = audit.action_groups || []
  if (!groups.length) return '<div class="panel empty">No open action groups in this audit.</div>'
  return `<div class="action-list">${groups.map((group) => `
    <article class="action-card">
      <div class="action-head"><span class="badge ${severityClass(group.severity)}">${escapeHTML(group.severity)}</span><span>${group.family === 'monitoring-reference-failure' ? 'MONITORING FAILURE · ' : ''}${group.finding_count} findings</span></div>
      <h2>${escapeHTML(group.title)}</h2>
      <p>${escapeHTML(group.consequence)}</p>
      <dl><dt>First step</dt><dd>${escapeHTML(group.first_step)}</dd><dt>Verify</dt><dd>${escapeHTML(group.verification)}</dd></dl>
      <div class="action-foot"><code>${escapeHTML(group.family)}</code>${group.family === 'service-coverage-gap' ? '<button class="text-button" data-open-view="coverage">Open coverage</button>' : ''}</div>
    </article>`).join('')}</div>`
}

function visibility() {
  const item = audit.inventory_visibility || {}
  const dimensions = item.unverified_dimensions || []
  return `<div class="panel visibility"><div><span class="badge evidence">${escapeHTML(item.state || 'NOT_PROVEN_COMPLETE')}</span><h2>Inventory visibility</h2><p>${escapeHTML(item.basis || '')}</p>${item.access_guidance ? `<p class="next">${escapeHTML(item.access_guidance)}</p>` : ''}${item.ownership_guidance ? `<p class="next">${escapeHTML(item.ownership_guidance)}</p>` : ''}</div><div class="visibility-counts"><strong>${item.observed_resource_count || 0}</strong><span>observed resources</span><strong>${item.observed_relationship_count || 0}</strong><span>relationships</span></div>${dimensions.length ? `<p class="muted">Still unverified: ${dimensions.map(escapeHTML).join(', ')}.</p>` : ''}</div>`
}

function coverageRows() {
  const assessments = report.coverage?.assessments || []
  const rows = []
  assessments.forEach((assessment) => {
    ;(assessment.signals || []).forEach((signal) => {
      if (signal.state !== 'MISSING' && signal.state !== 'UNKNOWN') return
      rows.push({
        service: assessment.service_name || assessment.service_id,
        service_id: assessment.service_id,
        expectation_id: assessment.expectation_id,
        signal: signal.signal,
        state: signal.state,
        identity: `${assessment.service_identity_source || 'unknown'} / ${assessment.service_identity_confidence || 'unknown'}`,
      })
    })
  })
  rows.sort((left, right) => left.state.localeCompare(right.state) || left.signal.localeCompare(right.signal) || left.service.localeCompare(right.service))
  return rows
}

function connectorCommand(signal) {
  const commands = {
    alerts: 'monicheck local --alertmanager-url http://127.0.0.1:9093',
    dashboards: 'monicheck local --grafana-url http://127.0.0.1:3000',
    metrics: 'monicheck local --prometheus-url http://127.0.0.1:9090',
    traces: 'Add a Tempo, Jaeger, or supported trace connector in monicheck.yaml',
    logs: 'Add a Loki or supported log connector in monicheck.yaml',
    profiles: 'Add a Pyroscope connector in monicheck.yaml',
  }
  return commands[String(signal || '').toLowerCase()] || 'Add the evidence source for this signal in monicheck.yaml'
}

function coverageView() {
  const rows = coverageRows()
  const missing = rows.filter((row) => row.state === 'MISSING')
  const unknown = rows.filter((row) => row.state === 'UNKNOWN')
  const signalCounts = rows.reduce((result, row) => {
    const key = `${row.signal}:${row.state}`
    result[key] = (result[key] || 0) + 1
    return result
  }, {})
  const topMissing = missing.slice(0, 10)
  const topUnknown = unknown.slice(0, 10)
  const topRows = [...topMissing, ...topUnknown]
  return `${metrics()}
    <div class="panel coverage-summary">
      <div><span class="badge evidence">${escapeHTML(report.coverage_evidence_state || 'UNKNOWN')}</span><h2>Coverage evidence</h2><p>Coverage is calculated across ${report.coverage_evaluable_signals || 0} evaluable required service-signal pairs. UNKNOWN signals are excluded from the denominator and are never counted as healthy.</p></div>
      <div class="coverage-totals"><strong>${missing.length}</strong><span>missing rows</span><strong>${unknown.length}</strong><span>unknown rows</span></div>
      <button class="button" data-open-view="agent">Open related actions</button>
    </div>
    <div class="signal-strip">${Object.entries(signalCounts).map(([key, count]) => { const [signal, state] = key.split(':'); return `<span><strong>${count}</strong> ${escapeHTML(signal)} ${escapeHTML(state.toLowerCase())}</span>` }).join('')}</div>
    ${topRows.length ? `<div class="panel table-panel"><table><thead><tr><th>State</th><th>Service</th><th>Signal</th><th>Identity evidence</th><th>Next action</th></tr></thead><tbody>${topRows.map((row) => `<tr><td><span class="badge ${severityClass(row.state)}">${escapeHTML(row.state)}</span></td><td>${escapeHTML(row.service)}</td><td>${escapeHTML(row.signal)}</td><td>${escapeHTML(row.identity)}</td><td>${row.state === 'UNKNOWN' ? `<code>${escapeHTML(connectorCommand(row.signal))}</code>` : `<button class="text-button" data-copy-exception="${escapeHTML(encodeURIComponent(JSON.stringify(row)))}">Copy exception YAML</button>`}</td></tr>`).join('')}</tbody></table></div>` : '<div class="panel empty">No missing or unknown service signals.</div>'}
    ${rows.length > topRows.length ? `<p class="muted">Showing up to 10 missing and 10 unknown rows (${topRows.length} of ${rows.length} actionable service-signal rows).</p>` : ''}`
}

function render(view) {
  title.textContent = view === 'agent' ? 'Agent audit' : view[0].toUpperCase() + view.slice(1)
  if (view === 'overview') content.innerHTML = metrics() + table(report.priority_findings || [], [['Severity', 'severity'], ['Finding', 'type'], ['Resource', 'resource'], ['Recommendation', 'recommendation']])
  if (view === 'agent') {
    const persisted = status.state_source === 'PERSISTED_AGENT_AUDIT'
    content.innerHTML = `${metrics()}<div class="panel agent-state"><strong>${persisted ? 'Persisted Agent audit' : 'Current Local audit'}</strong><p>Monitoring failures appear before hygiene advice. This view reads the same durable evidence used by the MCP tools and does not contact providers or rerun analyzers.</p></div><div class="section-heading"><div><p class="eyebrow">MONITORING CONTROL</p><h2>What is broken, unguarded, or unproven?</h2></div><span>${audit.action_groups?.length || 0} groups</span></div>${actionGroups()}${visibility()}`
  }
  if (view === 'findings') content.innerHTML = table(report.priority_findings || [], [['Severity', 'severity'], ['Finding', 'type'], ['Resource', 'resource'], ['Risk', 'risk_score'], ['Recommendation', 'recommendation']])
  if (view === 'coverage') content.innerHTML = coverageView()
  if (view === 'connectors') {
    const connectors = status.connectors || []
    content.innerHTML = status.state_source === 'PERSISTED_AGENT_AUDIT' && !connectors.length
      ? '<div class="panel empty"><strong>Live connector status is unavailable in serve-only mode.</strong><p>This view opened persisted audit evidence without contacting providers. Run a normal Local audit to refresh connector health and inventory visibility.</p></div>'
      : table(connectors, [['Group', 'group'], ['Connector', 'name'], ['Status', 'status'], ['Resources', 'resource_count'], ['Error', 'error']])
  }
}

function openView(view) {
  const button = document.querySelector(`nav button[data-view="${view}"]`)
  if (!button) return
  document.querySelector('nav .active').classList.remove('active')
  button.classList.add('active')
  const url = new URL(window.location.href)
  url.searchParams.set('view', view)
  window.history.replaceState({}, '', url)
  render(view)
}

document.querySelectorAll('nav button').forEach((button) => { button.onclick = () => openView(button.dataset.view) })
content.addEventListener('click', async (event) => {
  const viewButton = event.target.closest('[data-open-view]')
  if (viewButton) openView(viewButton.dataset.openView)
  const exceptionButton = event.target.closest('[data-copy-exception]')
  if (!exceptionButton) return
  const row = JSON.parse(decodeURIComponent(exceptionButton.dataset.copyException))
  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
  const yaml = `coverage_exceptions:\n  - expectation_id: ${row.expectation_id}\n    service_id: ${row.service_id}\n    signal: ${row.signal}\n    owner: CHANGE_ME\n    reason: CHANGE_ME\n    created_by: CHANGE_ME\n    expires_at: ${expires}\n`
  await navigator.clipboard.writeText(yaml)
  exceptionButton.textContent = 'Copied YAML'
})

const requested = new URLSearchParams(window.location.search).get('view')
if (requested) openView(requested)
document.querySelector('#refresh').onclick = load
load()

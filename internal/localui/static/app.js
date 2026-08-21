const content = document.querySelector('#content')
const title = document.querySelector('#title')
let report = {}
let status = {}

async function load() {
  try {
    ;[report, status] = await Promise.all([
      fetch('/api/v1/local/report').then((response) => response.json()),
      fetch('/api/v1/local/status').then((response) => response.json()),
    ])
    document.querySelector('#activation').hidden =
      !(status.connectors || []).some((item) => item.status === 'SUCCEEDED' || item.status === 'WARNING') ||
      !(report.resource_count > 0)
    render(active())
  } catch (_error) {
    content.innerHTML = '<div class="panel">Local report could not be loaded.</div>'
  }
}

function active() {
  return document.querySelector('nav .active').dataset.view
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
  return `<div class="panel"><table><thead><tr>${columns.map((column) => `<th>${column[0]}</th>`).join('')}</tr></thead><tbody>${rows.map((row) => `<tr>${columns.map((column) => `<td>${value(row[column[1]])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`
}

function render(view) {
  title.textContent = view === 'agent' ? 'Agent audit' : view[0].toUpperCase() + view.slice(1)
  if (view === 'overview') {
    content.innerHTML = metrics() + table(report.priority_findings || [], [['Severity', 'severity'], ['Finding', 'type'], ['Resource', 'resource'], ['Recommendation', 'recommendation']])
  }
  if (view === 'agent') {
    const persisted = status.state_source === 'PERSISTED_AGENT_AUDIT'
    content.innerHTML = metrics() + `<div class="panel agent-state"><strong>${persisted ? 'Persisted Agent audit' : 'Current Local audit'}</strong><p>This view reads the same durable evidence used by the MCP tools. Opening it does not contact providers or rerun analyzers.</p><p class="next">Inventory completeness is not assumed. Use the Agent's purpose-bound Service and entity queries for scoped drill-down; UNKNOWN remains distinct from MISSING.</p></div>`
  }
  if (view === 'findings') {
    content.innerHTML = table(report.priority_findings || [], [['Severity', 'severity'], ['Finding', 'type'], ['Resource', 'resource'], ['Risk', 'risk_score'], ['Recommendation', 'recommendation']])
  }
  if (view === 'coverage') {
    const unknown = report.coverage_unknown_signals || 0
    content.innerHTML = metrics() + `<div class="panel"><strong>Coverage evidence</strong><p>${report.coverage_evidence_state || 'UNKNOWN'} · ${report.coverage_evidence_completeness_percent || 0}% complete</p><p>Evaluable coverage: ${report.coverage_percent || 0}%. ${report.coverage_missing_signals || 0} missing signals, ${unknown} unknown.</p>${unknown ? '<p class="next">Next: connect the evidence sources for unknown signal types before treating evaluable coverage as estate-wide coverage.</p>' : ''}</div>`
  }
  if (view === 'connectors') {
    content.innerHTML = table(status.connectors || [], [['Group', 'group'], ['Connector', 'name'], ['Status', 'status'], ['Resources', 'resource_count'], ['Error', 'error']])
  }
}

document.querySelectorAll('nav button').forEach((button) => {
  button.onclick = () => {
    document.querySelector('nav .active').classList.remove('active')
    button.classList.add('active')
    const url = new URL(window.location.href)
    url.searchParams.set('view', button.dataset.view)
    window.history.replaceState({}, '', url)
    render(active())
  }
})

const requested = new URLSearchParams(window.location.search).get('view')
const requestedButton = requested && document.querySelector(`nav button[data-view="${requested}"]`)
if (requestedButton) {
  document.querySelector('nav .active').classList.remove('active')
  requestedButton.classList.add('active')
}
document.querySelector('#refresh').onclick = load
load()

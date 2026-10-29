import { useCallback, useEffect, useMemo, useState } from 'react'
import './App.css'

const API = '/api'

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  })

  const text = await response.text()
  let data = null

  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = text
  }

  if (!response.ok) {
    const detail = data && typeof data === 'object' ? data.detail : null
    throw new Error(
      typeof detail === 'string'
        ? detail
        : `Request failed (${response.status})`,
    )
  }

  return data
}

function dateLabel(value) {
  if (!value) return '—'

  const date = new Date(value)

  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleString()
}

function Badge({ value }) {
  const raw = String(value ?? 'UNKNOWN')
  const tone = raw.toLowerCase().replace(/[^a-z0-9]+/g, '-')

  return (
    <span className={`badge badge-${tone}`}>
      {raw.replaceAll('_', ' ')}
    </span>
  )
}

function StatCard({ label, value, note, icon }) {
  return (
    <article className="stat-card">
      <div className="stat-top">
        <span>{label}</span>
        <span className="stat-icon">{icon}</span>
      </div>
      <strong>{value ?? 0}</strong>
      {note && <small>{note}</small>}
    </article>
  )
}

function Empty({
  title = 'Nothing to show yet',
  detail = 'Data will appear here when it is available.',
}) {
  return (
    <div className="empty-state">
      <span className="empty-mark">◇</span>
      <strong>{title}</strong>
      <p>{detail}</p>
    </div>
  )
}

function ErrorNotice({ error }) {
  if (!error) return null

  return (
    <div className="notice error-notice" role="alert">
      <strong>Request failed</strong>
      <span>{error}</span>
    </div>
  )
}

function Loading({ label = 'Loading data…' }) {
  return (
    <div className="loading-state">
      <span className="spinner" />
      {label}
    </div>
  )
}

function PageHeading({ eyebrow, title, description, action }) {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action && <div className="heading-action">{action}</div>}
    </div>
  )
}

function Panel({ title, subtitle, action, children, className = '' }) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-heading">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  )
}

function DataTable({
  columns,
  rows,
  emptyTitle,
  emptyDetail,
  rowKey,
}) {
  if (!rows?.length) {
    return (
      <Empty
        title={emptyTitle || 'No records found'}
        detail={
          emptyDetail ||
          'Try changing the filters or run a check first.'
        }
      />
    )
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key}>{column.label}</th>
            ))}
          </tr>
        </thead>

        <tbody>
          {rows.map((row, index) => (
            <tr
              key={rowKey ? rowKey(row) : (row.id ?? index)}
            >
              {columns.map((column) => (
                <td key={column.key}>
                  {column.render
                    ? column.render(row)
                    : (row[column.key] ?? '—')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* ---------------- DASHBOARD ---------------- */

function Dashboard({ refreshKey, onNavigate }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')

    try {
      const result = await apiRequest('/dashboard/data')
      setData(result)
    } catch (error) {
      setError(error.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load, refreshKey])

  const summary = data?.summary || {}
  const severity = summary.findings_by_severity || {}
  const maxSeverity = Math.max(
    1,
    ...Object.values(severity).map(Number),
  )

  return (
    <>
      <PageHeading
        eyebrow="OVERVIEW"
        title="Security dashboard"
        description="A live overview of your registered lab applications, scan activity and recorded security findings."
        action={
          <button
            className="button button-secondary"
            onClick={load}
          >
            ↻ Refresh
          </button>
        }
      />

      <ErrorNotice error={error} />

      {loading && !data ? (
        <Loading />
      ) : (
        <>
          <div className="stats-grid">
            <StatCard
              label="Applications"
              value={summary.total_applications}
              note={`${summary.active_applications || 0} active`}
              icon="▦"
            />

            <StatCard
              label="Total scans"
              value={summary.total_scans}
              note={`${summary.completed_scans || 0} completed`}
              icon="⌁"
            />

            <StatCard
              label="Recorded findings"
              value={summary.total_recorded_findings}
              note={`${summary.verification_attempts || 0} verification attempts`}
              icon="⚑"
            />

            <StatCard
              label="Regression candidates"
              value={summary.regression_candidates}
              note="Based on recorded verifications"
              icon="↗"
            />
          </div>

          <div className="dashboard-grid">
            <Panel
              title="Findings by severity"
              subtitle="Counts of stored finding records"
            >
              {Object.keys(severity).length ? (
                <div className="severity-list">
                  {Object.entries(severity)
                    .sort(
                      (a, b) =>
                        [
                          'critical',
                          'high',
                          'medium',
                          'low',
                          'informational',
                          'info',
                        ].indexOf(a[0].toLowerCase()) -
                        [
                          'critical',
                          'high',
                          'medium',
                          'low',
                          'informational',
                          'info',
                        ].indexOf(b[0].toLowerCase()),
                    )
                    .map(([name, count]) => (
                      <div className="severity-row" key={name}>
                        <span>{name}</span>

                        <div className="bar-track">
                          <div
                            className={`bar-fill severity-${name.toLowerCase()}`}
                            style={{
                              width: `${Math.max(
                                3,
                                (Number(count) / maxSeverity) * 100,
                              )}%`,
                            }}
                          />
                        </div>

                        <strong>{count}</strong>
                      </div>
                    ))}
                </div>
              ) : (
                <Empty
                  title="No findings recorded"
                  detail="Findings will be summarized after they are imported or created."
                />
              )}

              <button
                className="text-button"
                onClick={() => onNavigate('findings')}
              >
                View findings →
              </button>
            </Panel>

            <Panel
              title="Scan status"
              subtitle="Overview of recorded scan runs"
            >
              <div className="status-summary">
                {[
                  [
                    'Completed',
                    summary.completed_scans || 0,
                    'completed',
                  ],
                  [
                    'Failed',
                    summary.failed_scans || 0,
                    'failed',
                  ],
                  [
                    'Other / in progress',
                    Math.max(
                      0,
                      (summary.total_scans || 0) -
                        (summary.completed_scans || 0) -
                        (summary.failed_scans || 0),
                    ),
                    'other',
                  ],
                ].map(([label, value, tone]) => (
                  <div className="status-item" key={label}>
                    <span className={`status-dot ${tone}`} />
                    <span>{label}</span>
                    <strong>{value}</strong>
                  </div>
                ))}
              </div>

              <button
                className="text-button"
                onClick={() => onNavigate('scans')}
              >
                Open scan history →
              </button>
            </Panel>
          </div>

          <Panel
            title="Recent scans"
            subtitle="Latest scan runs in your database"
            action={
              <button
                className="text-button"
                onClick={() => onNavigate('scans')}
              >
                View all →
              </button>
            }
          >
            <DataTable
              rows={data?.recent_scans || []}
              columns={[
                {
                  key: 'id',
                  label: 'Scan ID',
                  render: (row) => <strong>#{row.id}</strong>,
                },
                {
                  key: 'application_name',
                  label: 'Application',
                },
                { key: 'scanner', label: 'Scanner' },
                {
                  key: 'started_at',
                  label: 'Started',
                  render: (row) => dateLabel(row.started_at),
                },
                {
                  key: 'status',
                  label: 'Status',
                  render: (row) => <Badge value={row.status} />,
                },
              ]}
              emptyTitle="No scans yet"
              emptyDetail="Run a connectivity check or create a scan from Applications."
            />
          </Panel>

          <Panel
            title="Recent findings"
            subtitle="Most recently recorded vulnerability findings"
            action={
              <button
                className="text-button"
                onClick={() => onNavigate('findings')}
              >
                View all →
              </button>
            }
          >
            <DataTable
              rows={data?.recent_findings || []}
              columns={[
                {
                  key: 'title',
                  label: 'Finding',
                  render: (row) => (
                    <div className="cell-primary">
                      <strong>{row.title}</strong>
                      <small>Scan #{row.scan_id}</small>
                    </div>
                  ),
                },
                {
                  key: 'severity',
                  label: 'Severity',
                  render: (row) => <Badge value={row.severity} />,
                },
                {
                  key: 'status',
                  label: 'Status',
                  render: (row) => <Badge value={row.status} />,
                },
                { key: 'source', label: 'Source' },
                {
                  key: 'affected_url',
                  label: 'Affected URL',
                  render: (row) => (
                    <span className="url-cell">
                      {row.affected_url || '—'}
                    </span>
                  ),
                },
              ]}
              emptyTitle="No findings yet"
            />
          </Panel>

          <Panel
            title="Regression candidates"
            subtitle="Findings detected in a completed scan after a recorded verified resolution"
            action={
              <button
                className="text-button"
                onClick={() => onNavigate('regressions')}
              >
                Compare scans →
              </button>
            }
          >
            <DataTable
              rows={data?.regressions || []}
              columns={[
                { key: 'title', label: 'Finding' },
                {
                  key: 'severity',
                  label: 'Severity',
                  render: (row) => <Badge value={row.severity} />,
                },
                {
                  key: 'scan_id',
                  label: 'Latest scan',
                  render: (row) => `#${row.scan_id}`,
                },
                {
                  key: 'status',
                  label: 'Status',
                  render: (row) => <Badge value={row.status} />,
                },
              ]}
              emptyTitle="No regression candidates"
              emptyDetail="This is expected until a finding has a recorded verified resolution and is detected again in a later completed scan."
            />
          </Panel>

          <div className="last-updated">
            Dashboard data generated {dateLabel(data?.generated_at)}
          </div>
        </>
      )}
    </>
  )
}

/* ---------------- APPLICATIONS ---------------- */

function Applications({ refreshApp }) {
  const [apps, setApps] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(null)
  const [name, setName] = useState('')
  const [baseUrl, setBaseUrl] = useState(
    'http://127.0.0.1:3000',
  )
  const [results, setResults] = useState({})
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')

    try {
      setApps(await apiRequest('/applications'))
    } catch (error) {
      setError(error.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load, refreshApp])

  async function register(event) {
    event.preventDefault()
    setError('')
    setNotice('')

    try {
      await apiRequest('/applications', {
        method: 'POST',
        body: JSON.stringify({
          name,
          base_url: baseUrl,
          is_active: true,
        }),
      })

      setName('')
      setNotice('Application registered successfully.')
      await load()
    } catch (error) {
      setError(error.message)
    }
  }

  async function toggle(app) {
    setBusy(app.id)
    setError('')
    setNotice('')

    try {
      await apiRequest(`/applications/${app.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          is_active: !app.is_active,
        }),
      })

      setNotice(
        `${app.name} is now ${
          app.is_active ? 'inactive' : 'active'
        }.`,
      )

      await load()
    } catch (error) {
      setError(error.message)
    } finally {
      setBusy(null)
    }
  }

  async function connectivity(app) {
    setBusy(app.id)
    setError('')
    setNotice('')

    try {
      const result = await apiRequest(
        `/applications/${app.id}/connectivity-check`,
        { method: 'POST' },
      )

      setResults((previous) => ({
        ...previous,
        [app.id]: result,
      }))

      setNotice(`Connectivity check finished for ${app.name}.`)
    } catch (error) {
      setError(error.message)
    } finally {
      setBusy(null)
    }
  }

  async function createScan(app) {
    setBusy(app.id)
    setError('')
    setNotice('')

    try {
      const scan = await apiRequest(
        `/applications/${app.id}/scans`,
        { method: 'POST' },
      )

      setNotice(
        `Queued scan #${scan.id}. Use Scan History to run its connectivity assessment.`,
      )

      await load()
    } catch (error) {
      setError(error.message)
    } finally {
      setBusy(null)
    }
  }

  const filtered = apps.filter((app) =>
    `${app.name} ${app.base_url} ${app.id}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  )

  return (
    <>
      <PageHeading
        eyebrow="TARGET MANAGEMENT"
        title="Applications"
        description="Manage local lab targets that WebShield is allowed to assess."
        action={
          <button
            className="button button-secondary"
            onClick={load}
          >
            ↻ Refresh
          </button>
        }
      />

      <ErrorNotice error={error} />

      {notice && (
        <div className="notice success-notice">
          <strong>Done</strong>
          <span>{notice}</span>
          <button
            aria-label="Dismiss"
            onClick={() => setNotice('')}
          >
            ×
          </button>
        </div>
      )}

      <div className="application-layout">
        <Panel
          title="Register an application"
          subtitle="Only local lab URLs are accepted by the current backend."
        >
          <form className="form-stack" onSubmit={register}>
            <label>
              Application name
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="e.g. OWASP Juice Shop"
                required
                maxLength={120}
              />
            </label>

            <label>
              Base URL
              <input
                value={baseUrl}
                onChange={(event) => setBaseUrl(event.target.value)}
                placeholder="http://127.0.0.1:3000"
                required
                type="url"
              />
            </label>

            <div className="helper-note">
              Allowed hosts: localhost, 127.0.0.1 and ::1.
              Remote targets are rejected by the backend.
            </div>

            <button className="button button-primary" type="submit">
              ＋ Register application
            </button>
          </form>
        </Panel>

        <Panel
          title="Application inventory"
          subtitle={`${apps.length} registered target${
            apps.length === 1 ? '' : 's'
          }`}
          className="application-inventory"
        >
          <div className="toolbar">
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search applications…"
              aria-label="Search applications"
            />
          </div>

          {loading ? (
            <Loading />
          ) : filtered.length ? (
            <div className="app-list">
              {filtered.map((app) => (
                <article className="app-card" key={app.id}>
                  <div className="app-card-top">
                    <div className="app-symbol">⌘</div>

                    <div className="app-card-title">
                      <strong>{app.name}</strong>
                      <small>Application #{app.id}</small>
                    </div>

                    <Badge
                      value={app.is_active ? 'ACTIVE' : 'INACTIVE'}
                    />
                  </div>

                  <div className="app-url">{app.base_url}</div>

                  {results[app.id] && (
                    <div
                      className={`connectivity-result ${
                        results[app.id].reachable
                          ? 'reachable'
                          : 'unreachable'
                      }`}
                    >
                      <strong>
                        {results[app.id].reachable
                          ? 'Reachable'
                          : 'Unreachable'}
                      </strong>
                      <span>{results[app.id].message}</span>
                      <small>
                        HTTP {results[app.id].http_status ?? '—'} ·{' '}
                        {results[app.id].elapsed_ms ?? '—'} ms
                      </small>
                    </div>
                  )}

                  <div className="app-actions">
                    <button
                      className="button button-secondary"
                      disabled={busy === app.id || !app.is_active}
                      onClick={() => connectivity(app)}
                    >
                      {busy === app.id
                        ? 'Working…'
                        : 'Check connectivity'}
                    </button>

                    <button
                      className="button button-secondary"
                      disabled={busy === app.id || !app.is_active}
                      onClick={() => createScan(app)}
                    >
                      Queue scan
                    </button>

                    <button
                      className="button button-quiet"
                      disabled={busy === app.id}
                      onClick={() => toggle(app)}
                    >
                      {app.is_active ? 'Deactivate' : 'Activate'}
                    </button>
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <Empty
              title="No matching applications"
              detail="Register a local lab application or adjust your search."
            />
          )}
        </Panel>
      </div>
    </>
  )
}

/* ---------------- SCAN HISTORY ---------------- */

function ScanHistory({ refreshKey, onRefresh }) {
  const [scans, setScans] = useState([])
  const [apps, setApps] = useState([])
  const [filter, setFilter] = useState('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(null)
  const [detail, setDetail] = useState(null)
  const [connectivity, setConnectivity] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')

    try {
      const [scanData, appData] = await Promise.all([
        apiRequest(
          filter === 'all'
            ? '/scans'
            : `/scans?application_id=${filter}`,
        ),
        apiRequest('/applications'),
      ])

      setScans(scanData)
      setApps(appData)
    } catch (error) {
      setError(error.message)
    } finally {
      setLoading(false)
    }
  }, [filter])

  useEffect(() => {
    load()
  }, [load, refreshKey])

  async function viewScan(scan) {
    setError('')
    setConnectivity(null)

    try {
      const [scanInfo, result] = await Promise.all([
        apiRequest(`/scans/${scan.id}`),
        apiRequest(`/scans/${scan.id}/connectivity-result`).catch(
          () => null,
        ),
      ])

      setDetail(scanInfo)
      setConnectivity(result)
    } catch (error) {
      setError(error.message)
    }
  }

  async function runConnectivity(scan) {
    setBusy(scan.id)
    setError('')

    try {
      await apiRequest(`/scans/${scan.id}/run-connectivity`, {
        method: 'POST',
      })

      await load()
      await viewScan(scan)
      onRefresh()
    } catch (error) {
      setError(error.message)
    } finally {
      setBusy(null)
    }
  }

  const appName = (id) =>
    apps.find((app) => app.id === id)?.name ||
    `Application #${id}`

  return (
    <>
      <PageHeading
        eyebrow="ACTIVITY"
        title="Scan history"
        description="Review scan runs and run the available connectivity assessment for queued scans."
        action={
          <button
            className="button button-secondary"
            onClick={load}
          >
            ↻ Refresh
          </button>
        }
      />

      <ErrorNotice error={error} />

      <Panel
        title="Recorded scan runs"
        subtitle="Scan history is loaded directly from the backend."
      >
        <div className="toolbar">
          <label className="filter-label">
            Application
            <select
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
            >
              <option value="all">All applications</option>
              {apps.map((app) => (
                <option value={app.id} key={app.id}>
                  {app.name}
                </option>
              ))}
            </select>
          </label>

          <span className="result-count">{scans.length} scans</span>
        </div>

        {loading ? (
          <Loading />
        ) : (
          <DataTable
            rows={scans}
            columns={[
              {
                key: 'id',
                label: 'Scan',
                render: (row) => <strong>#{row.id}</strong>,
              },
              {
                key: 'application_id',
                label: 'Application',
                render: (row) => appName(row.application_id),
              },
              { key: 'scanner', label: 'Scanner' },
              {
                key: 'started_at',
                label: 'Started',
                render: (row) => dateLabel(row.started_at),
              },
              {
                key: 'completed_at',
                label: 'Completed',
                render: (row) => dateLabel(row.completed_at),
              },
              {
                key: 'status',
                label: 'Status',
                render: (row) => <Badge value={row.status} />,
              },
              {
                key: 'actions',
                label: 'Actions',
                render: (row) => (
                  <div className="inline-actions">
                    <button
                      className="small-button"
                      onClick={() => viewScan(row)}
                    >
                      Details
                    </button>

                    {row.status === 'QUEUED' && (
                      <button
                        className="small-button primary-small"
                        disabled={busy === row.id}
                        onClick={() => runConnectivity(row)}
                      >
                        {busy === row.id
                          ? 'Running…'
                          : 'Run connectivity'}
                      </button>
                    )}
                  </div>
                ),
              },
            ]}
            emptyTitle="No scan runs"
            emptyDetail="Register an application and queue a scan to begin."
          />
        )}
      </Panel>

      {detail && (
        <Panel
          title={`Scan #${detail.id} details`}
          subtitle={appName(detail.application_id)}
          action={
            <button
              className="text-button"
              onClick={() => {
                setDetail(null)
                setConnectivity(null)
              }}
            >
              Close ×
            </button>
          }
        >
          <div className="detail-grid">
            <div>
              <small>Status</small>
              <Badge value={detail.status} />
            </div>

            <div>
              <small>Scanner</small>
              <strong>{detail.scanner || '—'}</strong>
            </div>

            <div>
              <small>Started</small>
              <strong>{dateLabel(detail.started_at)}</strong>
            </div>

            <div>
              <small>Completed</small>
              <strong>{dateLabel(detail.completed_at)}</strong>
            </div>
          </div>

          {detail.error_message && (
            <div className="notice error-notice">
              <strong>Scan error</strong>
              <span>{detail.error_message}</span>
            </div>
          )}

          {connectivity && (
            <div className="connectivity-result">
              <strong>
                Connectivity result:{' '}
                {connectivity.reachable ? 'Reachable' : 'Unreachable'}
              </strong>
              <span>{connectivity.message}</span>
              <small>
                HTTP {connectivity.http_status ?? '—'} ·{' '}
                {connectivity.elapsed_ms ?? '—'} ms ·{' '}
                {dateLabel(connectivity.checked_at)}
              </small>
            </div>
          )}
        </Panel>
      )}
    </>
  )
}

/* ---------------- FINDINGS ---------------- */

function Findings({ refreshKey }) {
  const [findings, setFindings] = useState([])
  const [scans, setScans] = useState([])
  const [scanFilter, setScanFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState(null)
  const [attempts, setAttempts] = useState([])
  const [attemptLoading, setAttemptLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')

    try {
      const [findingData, scanData] = await Promise.all([
        apiRequest(
          scanFilter === 'all'
            ? '/findings'
            : `/findings?scan_id=${scanFilter}`,
        ),
        apiRequest('/scans'),
      ])

      setFindings(findingData)
      setScans(scanData)
    } catch (error) {
      setError(error.message)
    } finally {
      setLoading(false)
    }
  }, [scanFilter])

  useEffect(() => {
    load()
  }, [load, refreshKey])

  async function showAttempts(finding) {
    setSelected(finding)
    setAttempts([])
    setAttemptLoading(true)
    setError('')

    try {
      setAttempts(
        await apiRequest(
          `/findings/${finding.id}/verifications`,
        ),
      )
    } catch (error) {
      setError(error.message)
    } finally {
      setAttemptLoading(false)
    }
  }

  const filtered = useMemo(
    () =>
      findings.filter((finding) => {
        const matchesSeverity =
          severityFilter === 'all' ||
          String(finding.severity).toLowerCase() === severityFilter

        const matchesStatus =
          statusFilter === 'all' ||
          String(finding.status).toLowerCase() === statusFilter

        const text =
          `${finding.title} ${finding.affected_url} ${finding.source} ${finding.id}`
            .toLowerCase()

        return (
          matchesSeverity &&
          matchesStatus &&
          text.includes(search.toLowerCase())
        )
      }),
    [findings, severityFilter, statusFilter, search],
  )

  const statuses = [
    ...new Set(
      findings.map((finding) =>
        String(finding.status).toLowerCase(),
      ),
    ),
  ].sort()

  return (
    <>
      <PageHeading
        eyebrow="VULNERABILITY MANAGEMENT"
        title="Findings"
        description="Search recorded findings, filter by scan, severity and status, and inspect verification history."
        action={
          <button
            className="button button-secondary"
            onClick={load}
          >
            ↻ Refresh
          </button>
        }
      />

      <ErrorNotice error={error} />

      <Panel
        title="Finding inventory"
        subtitle={`${filtered.length} of ${findings.length} findings`}
      >
        <div className="filter-grid">
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search title, URL, source or ID…"
            aria-label="Search findings"
          />

          <select
            value={scanFilter}
            onChange={(event) => setScanFilter(event.target.value)}
            aria-label="Filter by scan"
          >
            <option value="all">All scans</option>
            {scans.map((scan) => (
              <option value={scan.id} key={scan.id}>
                Scan #{scan.id}
              </option>
            ))}
          </select>

          <select
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value)}
            aria-label="Filter by severity"
          >
            <option value="all">All severities</option>
            {[
              'critical',
              'high',
              'medium',
              'low',
              'informational',
              'info',
            ].map((severity) => (
              <option value={severity} key={severity}>
                {severity}
              </option>
            ))}
          </select>

          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            aria-label="Filter by status"
          >
            <option value="all">All statuses</option>
            {statuses.map((status) => (
              <option value={status} key={status}>
                {status.replaceAll('_', ' ')}
              </option>
            ))}
          </select>
        </div>

        {loading ? (
          <Loading />
        ) : (
          <DataTable
            rows={filtered}
            columns={[
              {
                key: 'id',
                label: 'ID',
                render: (row) => <strong>#{row.id}</strong>,
              },
              {
                key: 'title',
                label: 'Finding',
                render: (row) => (
                  <div className="cell-primary">
                    <strong>{row.title}</strong>
                    <small>Scan #{row.scan_id}</small>
                  </div>
                ),
              },
              {
                key: 'severity',
                label: 'Severity',
                render: (row) => <Badge value={row.severity} />,
              },
              {
                key: 'status',
                label: 'Status',
                render: (row) => <Badge value={row.status} />,
              },
              { key: 'source', label: 'Source' },
              {
                key: 'affected_url',
                label: 'Affected URL',
                render: (row) => (
                  <span className="url-cell">
                    {row.affected_url || '—'}
                  </span>
                ),
              },
              {
                key: 'actions',
                label: 'History',
                render: (row) => (
                  <button
                    className="small-button"
                    onClick={() => showAttempts(row)}
                  >
                    Verification history
                  </button>
                ),
              },
            ]}
            emptyTitle="No findings match"
            emptyDetail="Try clearing filters or importing findings from a completed scan."
          />
        )}
      </Panel>

      {selected && (
        <Panel
          title={`Verification history · Finding #${selected.id}`}
          subtitle={selected.title}
          action={
            <button
              className="text-button"
              onClick={() => setSelected(null)}
            >
              Close ×
            </button>
          }
        >
          {attemptLoading ? (
            <Loading />
          ) : (
            <DataTable
              rows={attempts}
              columns={[
                {
                  key: 'id',
                  label: 'Attempt',
                  render: (row) => `#${row.id ?? '—'}`,
                },
                {
                  key: 'scan_id',
                  label: 'Scan',
                  render: (row) =>
                    row.scan_id ? `#${row.scan_id}` : '—',
                },
                {
                  key: 'outcome',
                  label: 'Outcome',
                  render: (row) => (
                    <Badge value={row.outcome || row.status} />
                  ),
                },
                {
                  key: 'verified_at',
                  label: 'Verified at',
                  render: (row) => dateLabel(row.verified_at),
                },
                {
                  key: 'notes',
                  label: 'Notes',
                  render: (row) =>
                    row.notes || row.message || '—',
                },
              ]}
              emptyTitle="No verification attempts"
              emptyDetail="No verification attempts have been recorded for this finding."
            />
          )}
        </Panel>
      )}
    </>
  )
}

/* ---------------- REGRESSION COMPARISON ---------------- */

function Regressions({ refreshKey }) {
  const [scans, setScans] = useState([])
  const [latestId, setLatestId] = useState('')
  const [previousId, setPreviousId] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(true)
  const [comparing, setComparing] = useState(false)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')

    try {
      const all = await apiRequest('/scans')
      setScans(all)

      const completed = all.filter(
        (scan) => scan.status === 'COMPLETED',
      )

      if (!latestId && completed[0]) {
        setLatestId(String(completed[0].id))
      }

      if (!previousId && completed[1]) {
        setPreviousId(String(completed[1].id))
      }
    } catch (error) {
      setError(error.message)
    } finally {
      setLoading(false)
    }
  }, [latestId, previousId])

  useEffect(() => {
    load()
  }, [load, refreshKey])

  const completed = scans.filter(
    (scan) => scan.status === 'COMPLETED',
  )

  const latestScan = completed.find(
    (scan) => String(scan.id) === latestId,
  )

  const previousCandidates = completed.filter(
    (scan) =>
      scan.id !== Number(latestId) &&
      (!latestScan ||
        scan.application_id === latestScan.application_id),
  )

  async function compare(event) {
    event.preventDefault()
    setError('')
    setResult(null)
    setComparing(true)

    try {
      const path =
        `/findings/compare/${latestId}` +
        `?previous_scan_id=${previousId}`

      setResult(await apiRequest(path))
    } catch (error) {
      setError(error.message)
    } finally {
      setComparing(false)
    }
  }

  const summary = result?.summary || {}

  const groups = result
    ? [
        {
          title: 'New',
          key: 'new',
          tone: 'new',
          rows: result.new_findings || result.new || [],
        },
        {
          title: 'Recurring',
          key: 'recurring',
          tone: 'recurring',
          rows:
            result.recurring_findings ||
            result.recurring ||
            [],
        },
        {
          title: 'Resolved candidates',
          key: 'resolved',
          tone: 'resolved',
          rows:
            result.resolved_findings ||
            result.resolved_candidates ||
            result.resolved ||
            [],
        },
        {
          title: 'Regressions',
          key: 'regression',
          tone: 'regression',
          rows:
            result.regression_findings ||
            result.regressions ||
            [],
        },
      ]
    : []

  return (
    <>
      <PageHeading
        eyebrow="FIX VERIFICATION"
        title="Regression comparison"
        description="Compare two completed scans of the same application using WebShield's finding-matching workflow."
        action={
          <button
            className="button button-secondary"
            onClick={load}
          >
            ↻ Refresh scans
          </button>
        }
      />

      <ErrorNotice error={error} />

      <Panel
        title="Choose scans"
        subtitle="Only completed scans are eligible for comparison."
      >
        {loading ? (
          <Loading />
        ) : (
          <form className="compare-form" onSubmit={compare}>
            <label>
              Latest scan
              <select
                required
                value={latestId}
                onChange={(event) => {
                  const value = event.target.value
                  setLatestId(value)
                  setResult(null)

                  const selectedScan = completed.find(
                    (scan) => String(scan.id) === value,
                  )

                  const previous = completed.find(
                    (scan) =>
                      scan.id !== Number(value) &&
                      (!selectedScan ||
                        scan.application_id ===
                          selectedScan.application_id),
                  )

                  setPreviousId(
                    previous ? String(previous.id) : '',
                  )
                }}
              >
                <option value="">Select latest scan</option>
                {completed.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    Scan #{scan.id} · App #{scan.application_id} ·{' '}
                    {scan.scanner}
                  </option>
                ))}
              </select>
            </label>

            <label>
              Previous scan
              <select
                required
                value={previousId}
                onChange={(event) => {
                  setPreviousId(event.target.value)
                  setResult(null)
                }}
              >
                <option value="">Select previous scan</option>
                {previousCandidates.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    Scan #{scan.id} · {scan.scanner}
                  </option>
                ))}
              </select>
            </label>

            <button
              className="button button-primary"
              type="submit"
              disabled={
                comparing ||
                !latestId ||
                !previousId ||
                latestId === previousId
              }
            >
              {comparing ? 'Comparing…' : 'Compare findings'}
            </button>
          </form>
        )}

        <div className="helper-note">
          The backend validates that both scans are completed and belong
          to the same application. The comparison uses the matching rules
          implemented in your API.
        </div>
      </Panel>

      {result && (
        <>
          <div className="comparison-meta">
            <span>
              Previous scan{' '}
              <strong>#{result.previous_scan_id ?? previousId}</strong>
            </span>
            <span>
              Latest scan{' '}
              <strong>#{result.latest_scan_id ?? latestId}</strong>
            </span>
            <span>
              Application{' '}
              <strong>
                #{result.application_id ?? latestScan?.application_id ?? '—'}
              </strong>
            </span>
          </div>

          <div className="stats-grid comparison-stats">
            <StatCard
              label="New findings"
              value={summary.new ?? 0}
              icon="＋"
            />
            <StatCard
              label="Recurring"
              value={summary.recurring ?? 0}
              icon="↻"
            />
            <StatCard
              label="Resolved candidates"
              value={summary.resolved_candidates ?? 0}
              icon="✓"
            />
            <StatCard
              label="Regressions"
              value={summary.regressions ?? 0}
              icon="↗"
            />
          </div>

          {groups.map((group) => (
            <Panel
              title={group.title}
              subtitle={`${Array.isArray(group.rows) ? group.rows.length : 0} item${Array.isArray(group.rows) && group.rows.length === 1 ? '' : 's'}`}
              key={group.key}
              className={`comparison-panel ${group.tone}`}
            >
              <DataTable
                rows={Array.isArray(group.rows) ? group.rows : []}
                columns={[
                  {
                    key: 'id',
                    label: 'Finding ID',
                    render: (row) =>
                      row.id
                        ? `#${row.id}`
                        : row.finding_id
                          ? `#${row.finding_id}`
                          : '—',
                  },
                  { key: 'title', label: 'Finding' },
                  {
                    key: 'severity',
                    label: 'Severity',
                    render: (row) => <Badge value={row.severity} />,
                  },
                  { key: 'source', label: 'Source' },
                  {
                    key: 'affected_url',
                    label: 'Affected URL',
                    render: (row) => (
                      <span className="url-cell">
                        {row.affected_url || '—'}
                      </span>
                    ),
                  },
                  {
                    key: 'status',
                    label: 'Status',
                    render: (row) => <Badge value={row.status} />,
                  },
                ]}
                emptyTitle={`No ${group.title.toLowerCase()}`}
                emptyDetail="No records were returned in this comparison category."
              />
            </Panel>
          ))}

          <details className="raw-details">
            <summary>View raw comparison response</summary>
            <pre>{JSON.stringify(result, null, 2)}</pre>
          </details>
        </>
      )}

      {!loading && completed.length < 2 && (
        <div className="notice info-notice">
          <strong>More scans needed</strong>
          <span>
            At least two completed scans for the same application are
            required to compare results.
          </span>
        </div>
      )}
    </>
  )
}

/* ---------------- APPLICATION NAVIGATION ---------------- */

const NAV = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: '◫',
    group: 'WORKSPACE',
  },
  {
    id: 'applications',
    label: 'Applications',
    icon: '▦',
    group: 'WORKSPACE',
  },
  {
    id: 'scans',
    label: 'Scan history',
    icon: '◷',
    group: 'ANALYSIS',
  },
  {
    id: 'findings',
    label: 'Findings',
    icon: '⚑',
    group: 'ANALYSIS',
  },
  {
    id: 'regressions',
    label: 'Regression comparison',
    icon: '⇄',
    group: 'ANALYSIS',
  },
]

export default function App() {
  const [page, setPage] = useState('dashboard')
  const [refreshKey, setRefreshKey] = useState(0)
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const current = NAV.find((item) => item.id === page) || NAV[0]

  function refreshAll() {
    setRefreshKey((value) => value + 1)
  }

  return (
    <div className="app-shell">
      <aside
        className={`sidebar ${sidebarOpen ? 'sidebar-open' : ''}`}
      >
        <div className="brand">
          <div className="brand-mark">
            <span>W</span>
          </div>
          <div>
            <strong>WebShield</strong>
            <small>SECURITY PLATFORM</small>
          </div>
        </div>

        <div className="workspace-label">
          WORKSPACE <span className="online-dot" />
        </div>

        {['WORKSPACE', 'ANALYSIS'].map((group) => (
          <nav className="nav-group" key={group} aria-label={group}>
            <div className="nav-caption">{group}</div>

            {NAV.filter((item) => item.group === group).map((item) => (
              <button
                key={item.id}
                className={`nav-item ${
                  page === item.id ? 'active' : ''
                }`}
                onClick={() => {
                  setPage(item.id)
                  setSidebarOpen(false)
                }}
              >
                <span className="nav-icon">{item.icon}</span>
                <span>{item.label}</span>
                {page === item.id && (
                  <span className="nav-active-mark" />
                )}
              </button>
            ))}
          </nav>
        ))}

        <div className="sidebar-bottom">
          <div className="security-status">
            <span className="status-pulse" />
            <div>
              <strong>Lab protection mode</strong>
              <small>Local targets only</small>
            </div>
          </div>

          <div className="sidebar-version">
            WEBSHIELD · LOCAL INSTANCE
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <button
            className="mobile-menu"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            aria-label="Toggle navigation"
          >
            ☰
          </button>

          <div className="breadcrumbs">
            <span>WebShield</span>
            <span className="crumb-divider">/</span>
            <strong>{current.label}</strong>
          </div>

          <div className="topbar-right">
            <span className="api-status">
              <span className="online-dot" />
              API connected via local proxy
            </span>
            <button className="avatar" title="Local workspace">
              H
            </button>
          </div>
        </header>

        <div className="page-content">
          {page === 'dashboard' && (
            <Dashboard
              refreshKey={refreshKey}
              onNavigate={setPage}
            />
          )}

          {page === 'applications' && (
            <Applications refreshApp={refreshKey} />
          )}

          {page === 'scans' && (
            <ScanHistory
              refreshKey={refreshKey}
              onRefresh={refreshAll}
            />
          )}

          {page === 'findings' && (
            <Findings refreshKey={refreshKey} />
          )}

          {page === 'regressions' && (
            <Regressions refreshKey={refreshKey} />
          )}

          <footer className="page-footer">
            <span>
              WebShield · Evidence-based vulnerability verification
            </span>
            <span>Use only on authorized local lab targets.</span>
          </footer>
        </div>
      </main>
    </div>
  )
}

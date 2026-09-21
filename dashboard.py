#!/usr/bin/env python3
"""
Dashboard web pentru monitorul de trafic.

Rulează în PARALEL cu watcher.py, într-un terminal separat:
  python3 dashboard.py

Deschide browser la: http://localhost:5000

Nu modifică baza de date - doar citește.
Compatibil cu watcher_v6.py (traffic_monitor.db).
"""

import sqlite3
import os
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from flask import Flask, jsonify, render_template_string

DB_PATH = "traffic_monitor.db"
ALERTS_LOG_PATH = "alerts.log"

app = Flask(__name__)


# ---------- Citire date ----------

def get_db():
    if not os.path.exists(DB_PATH):
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def read_recent_alerts(n=20) -> list[dict]:
    """Citește ultimele N alerte din alerts.log."""
    if not os.path.exists(ALERTS_LOG_PATH):
        return []
    lines = []
    with open(ALERTS_LOG_PATH, encoding="utf-8") as f:
        lines = f.readlines()
    alerts = []
    for line in reversed(lines[-n:]):
        line = line.strip()
        if not line:
            continue
        alerts.append({"raw": line})
    return alerts


def read_recent_inbound(conn, n=20) -> list[dict]:
    """Ultimele N conexiuni primite (atacuri potențiale)."""
    cur = conn.execute("""
        SELECT timestamp, process_name, local_port, remote_ip, remote_port
        FROM inbound_events
        ORDER BY id DESC LIMIT ?
    """, (n,))
    return [dict(row) for row in cur.fetchall()]


def read_process_summary(conn) -> list[dict]:
    """
    Rezumat per proces: total conexiuni externe unice din ultimele 24h,
    sortate după activitate, ca să vedem repede cine "vorbește" cel mai mult.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    cur = conn.execute("""
        SELECT
            process_name,
            COUNT(*) as total,
            COUNT(DISTINCT remote_ip) as unique_ips,
            MAX(timestamp) as last_seen
        FROM connections
        WHERE timestamp > ?
          AND remote_ip NOT LIKE '192.168.%'
          AND remote_ip NOT LIKE '10.%'
          AND remote_ip NOT LIKE '127.%'
          AND remote_ip NOT LIKE '172.1%'
          AND remote_ip NOT LIKE '172.2%'
          AND remote_ip NOT LIKE '172.3%'
          AND remote_ip NOT LIKE '::1%'
          AND remote_ip NOT LIKE '::ffff:127%'
        GROUP BY process_name
        ORDER BY total DESC
        LIMIT 15
    """, (cutoff,))
    return [dict(row) for row in cur.fetchall()]


def read_recent_new_connections(conn, n=30) -> list[dict]:
    """Ultimele N combinații (proces, IP) văzute pentru prima dată."""
    cur = conn.execute("""
        SELECT process_name, remote_ip, remote_hostname, first_seen_at
        FROM notified_pairs
        ORDER BY first_seen_at DESC LIMIT ?
    """, (n,))
    return [dict(row) for row in cur.fetchall()]


# ---------- API endpoints ----------

@app.route("/api/status")
def api_status():
    conn = get_db()
    if conn is None:
        return jsonify({"error": "traffic_monitor.db negăsit — pornește watcher.py mai întâi"})

    process_summary = read_process_summary(conn)
    inbound = read_recent_inbound(conn)
    new_conns = read_recent_new_connections(conn)
    alerts = read_recent_alerts()

    # număr total de conexiuni din ultimele 24h
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    cur = conn.execute("SELECT COUNT(*) FROM connections WHERE timestamp > ?", (cutoff,))
    total_24h = cur.fetchone()[0]

    conn.close()
    return jsonify({
        "total_connections_24h": total_24h,
        "process_summary": process_summary,
        "recent_inbound": inbound,
        "recent_new_connections": new_conns,
        "recent_alerts": alerts,
        "generated_at": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
    })


# ---------- Interfața web ----------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Traffic Monitor</title>
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --accent: #58a6ff;
    --danger: #f85149;
    --warning: #d29922;
    --ok: #3fb950;
    --mono: 'Courier New', monospace;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    line-height: 1.5;
  }

  header {
    border-bottom: 1px solid var(--border);
    padding: 16px 24px;
    display: flex;
    align-items: center;
    gap: 12px;
    position: sticky;
    top: 0;
    background: var(--bg);
    z-index: 10;
  }

  .logo { font-size: 18px; font-weight: 700; color: var(--accent); letter-spacing: -0.5px; }
  .logo span { color: var(--muted); font-weight: 400; }

  .status-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--ok);
    box-shadow: 0 0 6px var(--ok);
    animation: pulse 2s infinite;
    margin-left: auto;
  }
  .status-dot.error { background: var(--danger); box-shadow: 0 0 6px var(--danger); }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  .updated-at { color: var(--muted); font-size: 12px; font-family: var(--mono); }

  main { padding: 20px 24px; display: grid; gap: 20px; max-width: 1400px; margin: 0 auto; }

  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 900px) { .grid-2 { grid-template-columns: 1fr; } }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }

  .card-header {
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .card-title { font-weight: 600; font-size: 13px; color: var(--text); text-transform: uppercase; letter-spacing: 0.5px; }
  .card-count { margin-left: auto; font-family: var(--mono); font-size: 12px; color: var(--muted); }

  /* Stat cards */
  .stat-bar { display: flex; gap: 16px; flex-wrap: wrap; }

  .stat {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px 20px;
    flex: 1;
    min-width: 140px;
  }

  .stat-value { font-size: 28px; font-weight: 700; font-family: var(--mono); color: var(--accent); }
  .stat-label { color: var(--muted); font-size: 12px; margin-top: 4px; }

  /* Tabele */
  table { width: 100%; border-collapse: collapse; }

  th {
    padding: 8px 16px;
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid var(--border);
  }

  td {
    padding: 8px 16px;
    border-bottom: 1px solid #1c2128;
    font-size: 13px;
    font-family: var(--mono);
  }

  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(88, 166, 255, 0.04); }

  .proc-name { color: var(--accent); }
  .ip-addr { color: var(--text); }
  .muted { color: var(--muted); font-size: 11px; }
  .ts { color: var(--muted); font-size: 11px; }

  /* Badge de risc */
  .badge {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
  }
  .badge-danger { background: rgba(248, 81, 73, 0.15); color: var(--danger); border: 1px solid rgba(248,81,73,0.3); }
  .badge-warning { background: rgba(210, 153, 34, 0.15); color: var(--warning); border: 1px solid rgba(210,153,34,0.3); }

  /* Alerte */
  .alert-line {
    padding: 8px 16px;
    border-bottom: 1px solid #1c2128;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--muted);
  }
  .alert-line:last-child { border-bottom: none; }
  .alert-line.is-risk { color: var(--warning); }
  .alert-line.is-inbound { color: var(--danger); }

  .empty { padding: 20px 16px; color: var(--muted); font-style: italic; font-size: 13px; }

  /* Bara de progres pentru #conexiuni */
  .bar-wrap { display: flex; align-items: center; gap: 8px; }
  .bar { height: 4px; background: var(--border); border-radius: 2px; flex: 1; overflow: hidden; }
  .bar-fill { height: 100%; background: var(--accent); border-radius: 2px; transition: width 0.3s; }
  .bar-val { font-family: var(--mono); font-size: 11px; color: var(--muted); min-width: 40px; text-align: right; }
</style>
</head>
<body>

<header>
  <div class="logo">Traffic<span>Monitor</span></div>
  <div class="updated-at" id="updated-at">—</div>
  <div class="status-dot" id="status-dot"></div>
</header>

<main>

  <!-- Statistici rapide -->
  <div class="stat-bar" id="stat-bar">
    <div class="stat">
      <div class="stat-value" id="stat-total">—</div>
      <div class="stat-label">Conexiuni externe (24h)</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="stat-processes">—</div>
      <div class="stat-label">Procese active</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="stat-inbound">—</div>
      <div class="stat-label">Conexiuni primite (inbound)</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="stat-alerts">—</div>
      <div class="stat-label">Alerte în jurnal</div>
    </div>
  </div>

  <div class="grid-2">

    <!-- Procese active -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">Procese active (24h)</div>
        <div class="card-count" id="proc-count">—</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Proces</th>
            <th>Conexiuni</th>
            <th>IP-uri distincte</th>
            <th>Ultima activitate</th>
          </tr>
        </thead>
        <tbody id="proc-table"></tbody>
      </table>
    </div>

    <!-- Alerte -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">Jurnal alerte</div>
        <div class="card-count" id="alert-count">—</div>
      </div>
      <div id="alert-list"></div>
    </div>

  </div>

  <div class="grid-2">

    <!-- Conexiuni primite (inbound) -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">🔴 Conexiuni primite</div>
        <div class="card-count" id="inbound-count">—</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Sursă (atacator)</th>
            <th>Proces vizat</th>
            <th>Port local</th>
            <th>Când</th>
          </tr>
        </thead>
        <tbody id="inbound-table"></tbody>
      </table>
    </div>

    <!-- Conexiuni noi văzute -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">Conexiuni noi observate</div>
        <div class="card-count" id="newconn-count">—</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Proces</th>
            <th>Destinație</th>
            <th>Prima dată văzut</th>
          </tr>
        </thead>
        <tbody id="newconn-table"></tbody>
      </table>
    </div>

  </div>

</main>

<script>
function fmt_ts(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString('ro-RO', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
  } catch { return ts.substring(11,19); }
}

function max_conn(processes) {
  return Math.max(...processes.map(p => p.total), 1);
}

async function refresh() {
  try {
    const res = await fetch('/api/status');
    const d = await res.json();

    if (d.error) {
      document.getElementById('status-dot').className = 'status-dot error';
      document.getElementById('updated-at').textContent = d.error;
      return;
    }

    document.getElementById('status-dot').className = 'status-dot';
    document.getElementById('updated-at').textContent = 'actualizat la ' + d.generated_at;

    // Statistici
    document.getElementById('stat-total').textContent = d.total_connections_24h.toLocaleString();
    document.getElementById('stat-processes').textContent = d.process_summary.length;
    document.getElementById('stat-inbound').textContent = d.recent_inbound.length;
    document.getElementById('stat-alerts').textContent = d.recent_alerts.length;

    // Procese
    const maxConn = max_conn(d.process_summary);
    document.getElementById('proc-count').textContent = d.process_summary.length + ' procese';
    document.getElementById('proc-table').innerHTML = d.process_summary.map(p => `
      <tr>
        <td class="proc-name">${p.process_name}</td>
        <td>
          <div class="bar-wrap">
            <div class="bar"><div class="bar-fill" style="width:${Math.round(p.total/maxConn*100)}%"></div></div>
            <div class="bar-val">${p.total}</div>
          </div>
        </td>
        <td class="muted">${p.unique_ips}</td>
        <td class="ts">${fmt_ts(p.last_seen)}</td>
      </tr>
    `).join('') || '<tr><td colspan="4" class="empty">Nicio activitate înregistrată încă.</td></tr>';

    // Alerte
    document.getElementById('alert-count').textContent = d.recent_alerts.length + ' alerte';
    document.getElementById('alert-list').innerHTML = d.recent_alerts.length
      ? d.recent_alerts.map(a => {
          const cls = a.raw.includes('[INBOUND]') ? 'is-inbound'
                    : a.raw.includes('[RISC')     ? 'is-risk'
                    : '';
          return `<div class="alert-line ${cls}">${a.raw}</div>`;
        }).join('')
      : '<div class="empty">Nicio alertă înregistrată — bine!</div>';

    // Inbound
    document.getElementById('inbound-count').textContent = d.recent_inbound.length;
    document.getElementById('inbound-table').innerHTML = d.recent_inbound.map(c => `
      <tr>
        <td><span class="badge badge-danger">${c.remote_ip}</span></td>
        <td class="proc-name">${c.process_name || '—'}</td>
        <td class="muted">${c.local_port}</td>
        <td class="ts">${fmt_ts(c.timestamp)}</td>
      </tr>
    `).join('') || '<tr><td colspan="4" class="empty">Nicio conexiune primită.</td></tr>';

    // Conexiuni noi
    document.getElementById('newconn-count').textContent = d.recent_new_connections.length;
    document.getElementById('newconn-table').innerHTML = d.recent_new_connections.map(c => {
      const display = (c.remote_hostname && c.remote_hostname !== c.remote_ip)
        ? `<span style="color:var(--text)">${c.remote_hostname}</span><br><span class="muted">${c.remote_ip}</span>`
        : `<span class="ip-addr">${c.remote_ip}</span>`;
      return `
        <tr>
          <td class="proc-name">${c.process_name}</td>
          <td>${display}</td>
          <td class="ts">${fmt_ts(c.first_seen_at)}</td>
        </tr>`;
    }).join('') || '<tr><td colspan="3" class="empty">Nicio conexiune nouă încă.</td></tr>';

  } catch (e) {
    document.getElementById('status-dot').className = 'status-dot error';
    document.getElementById('updated-at').textContent = 'Eroare la conectare: ' + e.message;
  }
}

// Actualizare automată la fiecare 5 secunde
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


if __name__ == "__main__":
    print("[*] Dashboard pornit la http://localhost:5000")
    print("[*] Rulează în paralel cu watcher.py — nu modifică datele")
    print("[*] Actualizare automată la fiecare 5 secunde")
    print("[*] Ctrl+C pentru oprire\n")
    app.run(host="127.0.0.1", port=5000, debug=False)

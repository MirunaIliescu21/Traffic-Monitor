#!/usr/bin/env python3
"""
Etapa 3: Monitor continuu pe fundal.

- Rulează CONTINUU pe fundal, colectând tot traficul (ca collector.py)
- Notifică INFORMATIV, o singură dată, când vede o combinație
  (proces, IP) nouă - fără să blocheze, fără să ceară răspuns
- La fiecare ANALYSIS_INTERVAL_SECONDS, rulează analiza de risc
  (concentrare + beaconing + reputație, din baseline.py) pe datele
  proaspăt colectate și trimite o alertă ACTIVĂ doar dacă găsește
  ceva cu adevărat suspect (scor >= 50)

Rulare: sudo python3 watcher.py
Oprire: Ctrl+C
"""

import psutil
import sqlite3
import subprocess
import ipaddress
import hashlib
import os
import pwd
import time
from datetime import datetime, timezone
from collections import defaultdict

from baseline_v4 import (
    is_private_ip, analyze_process, deduplicate_into_sessions,
    MIN_SAMPLES_FOR_BASELINE,
)
from reputation import init_reputation_table

DB_PATH = "traffic_monitor.db"
POLL_INTERVAL_SECONDS = 3          # cât de des verificăm conexiunile active
ANALYSIS_INTERVAL_SECONDS = 120    # cât de des rulăm analiza de risc completă (2 minute)
RISK_ALERT_THRESHOLD = 50          # scor de la care trimitem alertă activă (nu doar informativă)


# ---------- Notificări desktop, corect configurate pentru sudo ----------

def get_desktop_user_env() -> dict:
    """
    Când scriptul rulează cu sudo, procesul e root și NU are acces la
    sesiunea grafică a utilizatorului (DBUS_SESSION_BUS_ADDRESS, DISPLAY).
    Reconstruim aceste variabile pentru utilizatorul original (cel care
    a dat sudo), ca notify-send să știe către ce desktop să trimită popup-ul.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user:
        return os.environ.copy()  # nu rulează cu sudo, mediul e deja corect

    try:
        uid = pwd.getpwnam(sudo_user).pw_uid
    except KeyError:
        return os.environ.copy()

    env = os.environ.copy()
    env["DISPLAY"] = env.get("DISPLAY", ":0")
    env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{uid}/bus"
    return env


def send_desktop_notification(title: str, message: str, urgency: str = "normal") -> None:
    """Trimite un popup nativ Ubuntu, rulat ca utilizatorul desktop, nu ca root."""
    sudo_user = os.environ.get("SUDO_USER")
    env = get_desktop_user_env()

    try:
        if sudo_user:
            # rulăm notify-send explicit ca utilizatorul original, nu ca root
            subprocess.run(
                ["sudo", "-u", sudo_user, "notify-send",
                 f"--urgency={urgency}", "--icon=dialog-information", title, message],
                env=env, timeout=3, check=False,
            )
        else:
            subprocess.run(
                ["notify-send", f"--urgency={urgency}", title, message],
                env=env, timeout=3, check=False,
            )
    except (FileNotFoundError, subprocess.SubprocessError):
        pass  # nu blocăm scriptul dacă notificarea eșuează


# ---------- Colectare (identică ca logică cu collector.py) ----------

def init_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            pid INTEGER,
            process_name TEXT,
            binary_path TEXT,
            binary_hash TEXT,
            local_ip TEXT,
            local_port INTEGER,
            remote_ip TEXT,
            remote_port INTEGER,
            protocol TEXT,
            status TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_process_time ON connections (process_name, timestamp)")
    # tabelă nouă: ținem minte ce combinații (proces, IP) am NOTIFICAT deja,
    # ca să nu trimitem popup de 50 ori pentru aceeași destinație
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notified_pairs (
            process_name TEXT NOT NULL,
            remote_ip TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            PRIMARY KEY (process_name, remote_ip)
        )
    """)
    conn.commit()


def hash_binary(path: str) -> str | None:
    if not path:
        return None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def get_process_info(pid: int, cache: dict) -> tuple[str, str, str]:
    if pid in cache:
        return cache[pid]
    try:
        proc = psutil.Process(pid)
        info = (proc.name(), proc.exe(), hash_binary(proc.exe()))
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        info = ("unknown", None, None)
    cache[pid] = info
    return info


def collect_and_notify(conn: sqlite3.Connection, process_cache: dict, notified_pairs: set) -> int:
    """
    O trecere de colectare: salvează toate conexiunile active (ca collector.py)
    și trimite notificare informativă pentru combinațiile (proces, IP) noi.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    rows = []

    for conn_info in psutil.net_connections(kind="inet"):
        if not conn_info.raddr or not conn_info.pid:
            continue

        remote_ip = conn_info.raddr.ip
        remote_port = conn_info.raddr.port
        pid = conn_info.pid

        name, exe_path, binary_hash = get_process_info(pid, process_cache)
        protocol = "TCP" if conn_info.type == 1 else "UDP"

        rows.append((
            timestamp, pid, name, exe_path, binary_hash,
            conn_info.laddr.ip if conn_info.laddr else None,
            conn_info.laddr.port if conn_info.laddr else None,
            remote_ip, remote_port, protocol, conn_info.status,
        ))

        # notificare INFORMATIVĂ (fără blocare), doar pentru IP-uri externe noi
        if is_private_ip(remote_ip):
            continue
        pair = (name, remote_ip)
        if pair in notified_pairs:
            continue

        notified_pairs.add(pair)
        conn.execute(
            "INSERT OR IGNORE INTO notified_pairs (process_name, remote_ip, first_seen_at) VALUES (?, ?, ?)",
            (name, remote_ip, timestamp)
        )
        send_desktop_notification(
            "Conexiune nouă observată",
            f"{name} -> {remote_ip}:{remote_port}",
            urgency="low",  # informativ, nu alarmant - nu cerem reacție
        )
        print(f"[info] Conexiune nouă: {name} -> {remote_ip}:{remote_port}")

    if rows:
        conn.executemany("""
            INSERT INTO connections (
                timestamp, pid, process_name, binary_path, binary_hash,
                local_ip, local_port, remote_ip, remote_port, protocol, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
        conn.commit()

    return len(rows)


# ---------- Analiză periodică de risc (reutilizează baseline.py) ----------

def run_risk_analysis(conn: sqlite3.Connection) -> None:
    """
    Rulează exact aceeași logică din baseline.py (concentrare, beaconing,
    reputație) pe datele acumulate până acum, și trimite o alertă ACTIVĂ
    (urgency=critical) doar pentru procesele cu scor >= RISK_ALERT_THRESHOLD.
    """
    cur = conn.execute("SELECT process_name, timestamp, remote_ip, remote_port FROM connections ORDER BY process_name, timestamp")
    by_process = defaultdict(list)
    for process_name, timestamp, remote_ip, remote_port in cur.fetchall():
        by_process[process_name].append({
            "timestamp": datetime.fromisoformat(timestamp),
            "remote_ip": remote_ip,
            "remote_port": remote_port,
        })

    all_destinations = defaultdict(set)
    for process_name, conns in by_process.items():
        for c in conns:
            all_destinations[c["remote_ip"]].add(process_name)

    print(f"\n[analiza] Rulez evaluarea de risc pe {len(by_process)} procese...")
    for process_name, conns in by_process.items():
        report = analyze_process(process_name, conns, all_destinations, conn)
        if report["risk_score"] >= RISK_ALERT_THRESHOLD:
            reasons_text = "; ".join(report["reasons"][:2])  # primele 2 motive, pe scurt
            print(f"[ALERTĂ] {process_name}: risc {report['risk_score']}/100 - {reasons_text}")
            send_desktop_notification(
                f"⚠️ Risc ridicat: {process_name}",
                f"Scor {report['risk_score']}/100 - {reasons_text}",
                urgency="critical",
            )
    print("[analiza] Terminat.\n")


# ---------- Bucla principală ----------

def main():
    print(f"[*] Pornesc monitorul continuu")
    print(f"[*] Polling conexiuni: {POLL_INTERVAL_SECONDS}s | Analiză risc: la fiecare {ANALYSIS_INTERVAL_SECONDS}s")
    print("[*] Ctrl+C pentru oprire\n")

    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    init_reputation_table(conn)

    # încărcăm ce combinații am notificat deja (din rulări anterioare)
    cur = conn.execute("SELECT process_name, remote_ip FROM notified_pairs")
    notified_pairs = {(row[0], row[1]) for row in cur.fetchall()}
    print(f"[*] {len(notified_pairs)} combinații (proces, IP) deja notificate anterior\n")

    process_cache: dict = {}
    last_analysis = time.time()

    try:
        while True:
            start = time.time()
            n = collect_and_notify(conn, process_cache, notified_pairs)

            if len(process_cache) > 500:
                process_cache.clear()

            if time.time() - last_analysis >= ANALYSIS_INTERVAL_SECONDS:
                run_risk_analysis(conn)
                last_analysis = time.time()

            elapsed = time.time() - start
            time.sleep(max(0, POLL_INTERVAL_SECONDS - elapsed))

    except KeyboardInterrupt:
        print("\n[*] Monitor oprit de utilizator.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()

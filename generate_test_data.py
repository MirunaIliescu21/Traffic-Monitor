#!/usr/bin/env python3
"""
Generează date de test în traffic_monitor.db, ca să poți testa
scriptul de baseline FĂRĂ să aștepți zile de colectare reală.

Simulează:
- firefox: trafic normal, variabil, către multe destinații (browsing obișnuit)
- apt: trafic ocazional, volum mediu, către mirror-uri Ubuntu
- suspicious_proc: un proces care face BEACONING - conexiuni la interval
  fix, volum mic și constant, către aceeași destinație. Exact tiparul
  unui reverse shell / C2 channel.

Rulare: python3 generate_test_data.py
"""

import sqlite3
import random
from datetime import datetime, timedelta, timezone

DB_PATH = "traffic_monitor.db"


def random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def init_db(conn: sqlite3.Connection) -> None:
    """Creează schema dacă nu există deja (aceeași ca în collector.py)."""
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
    conn.commit()


def generate():
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    conn.execute("DELETE FROM connections")  # curat, pornim de la zero

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=3)  # simulăm 3 zile de "istorie"
    rows = []

    # --- 1. Firefox: trafic normal de browsing, multe destinații diferite, volum variabil ---
    t = start
    while t < now:
        # activitate mai intensă ziua (8-23), aproape deloc noaptea - simulăm un tipar realist
        hour = t.hour
        if 8 <= hour <= 23:
            n_conns = random.randint(3, 15)
            for _ in range(n_conns):
                rows.append((
                    t.isoformat(), 1234, "firefox", "/usr/bin/firefox", "hash_firefox_v1",
                    "192.168.1.50", random.randint(40000, 60000),
                    random_ip(), random.choice([443, 443, 443, 80]),
                    "TCP", "ESTABLISHED"
                ))
        t += timedelta(minutes=random.randint(5, 20))

    # --- 2. apt: trafic ocazional, doar către câteva mirror-uri cunoscute ---
    known_mirrors = ["91.189.91.39", "91.189.91.40", "185.125.190.36"]
    t = start
    while t < now:
        if random.random() < 0.05:  # rar, doar la update-uri
            for _ in range(random.randint(2, 6)):
                rows.append((
                    t.isoformat(), 5678, "apt", "/usr/bin/apt", "hash_apt_v1",
                    "192.168.1.50", random.randint(40000, 60000),
                    random.choice(known_mirrors), 80,
                    "TCP", "ESTABLISHED"
                ))
        t += timedelta(hours=1)

    # --- 3. Procesul SUSPECT: beaconing la interval fix de 60s, către aceeași destinație ---
    # Acesta e "atacul" pe care baseline-ul ar trebui să-l semnaleze ca anomalie:
    # - destinație unică, necunoscută (nu apare la niciun alt proces)
    # - interval extrem de regulat (semn clasic de C2 automatizat, nu comportament uman)
    # - apare abia în ultima oră, ca un atac recent
    c2_ip = "203.0.113.77"  # IP de test (rezervat pentru documentație, TEST-NET-3)
    attack_start = now - timedelta(minutes=45)
    t = attack_start
    while t < now:
        rows.append((
            t.isoformat(), 9999, "suspicious_proc", "/tmp/.hidden/update_svc", "hash_suspicious_v1",
            "192.168.1.50", 54321,
            c2_ip, 4444,
            "TCP", "ESTABLISHED"
        ))
        t += timedelta(seconds=60)  # exact la 60 de secunde, semn de automatizare

    conn.executemany("""
        INSERT INTO connections (
            timestamp, pid, process_name, binary_path, binary_hash,
            local_ip, local_port, remote_ip, remote_port, protocol, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)
    conn.commit()

    print(f"[*] Generate {len(rows)} conexiuni de test în {DB_PATH}")
    print(f"[*] Procese simulate: firefox (normal), apt (normal, rar), suspicious_proc (BEACONING - atac simulat)")
    conn.close()


if __name__ == "__main__":
    generate()

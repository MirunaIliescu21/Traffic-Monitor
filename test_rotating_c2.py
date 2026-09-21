#!/usr/bin/env python3
"""
Test sintetic: simulează un malware "inteligent" care rotește între
MAI MULTE IP-uri C2 (nu unul singur), tocmai ca să evite detecția de
CONCENTRARE (distinct_ips <= 3 din baseline.py).

Întrebarea la care răspundem: dacă concentrarea nu-l prinde, îl prinde
totuși regula de REGULARITATE (beaconing)? Codul din baseline.py
calculează regularitatea pe TOATE conexiunile externe combinate,
indiferent de câte IP-uri distincte sunt - deci teoretic ar trebui
să prindă tiparul chiar și cu rotație.

Adaugă date DOAR pentru procesul de test, NU șterge restul bazei de date
(rulează alături de datele tale reale deja colectate).

Rulare: python3 test_rotating_c2.py
"""

import sqlite3
from datetime import datetime, timedelta, timezone

DB_PATH = "traffic_monitor.db"

# 5 IP-uri publice REALE (servere DNS publice cunoscute - sigure de folosit ca test,
# nu din blocurile rezervate pentru documentație care produc clasificări greșite)
C2_IPS = [
    "1.1.1.1",        # Cloudflare DNS
    "8.8.8.8",         # Google DNS
    "9.9.9.9",         # Quad9 DNS
    "208.67.222.222",  # OpenDNS
    "76.76.2.22",      # Control D DNS
]

INTERVAL_SECONDS = 45  # interval fix intre conexiuni, indiferent de IP
N_CONNECTIONS = 20     # 20 conexiuni = destule pentru un calcul de deviatie std solid


def generate():
    conn = sqlite3.connect(DB_PATH)
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

    now = datetime.now(timezone.utc)
    start = now - timedelta(seconds=INTERVAL_SECONDS * N_CONNECTIONS)

    rows = []
    t = start
    for i in range(N_CONNECTIONS):
        # rotește prin cele 5 IP-uri, în ordine (round-robin) - simulează
        # un malware care alternează destinația la fiecare conexiune
        ip = C2_IPS[i % len(C2_IPS)]
        rows.append((
            t.isoformat(), 8888, "rotating_c2_sim", "/tmp/.hidden/svc", "hash_rotating",
            "192.168.1.50", 55000 + i,
            ip, 443,
            "TCP", "ESTABLISHED"
        ))
        t += timedelta(seconds=INTERVAL_SECONDS)

    conn.executemany("""
        INSERT INTO connections (
            timestamp, pid, process_name, binary_path, binary_hash,
            local_ip, local_port, remote_ip, remote_port, protocol, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)
    conn.commit()

    print(f"[*] Adaugate {len(rows)} conexiuni pentru 'rotating_c2_sim'")
    print(f"[*] Rotatie intre {len(C2_IPS)} IP-uri diferite, interval fix {INTERVAL_SECONDS}s")
    print(f"[*] Distinct IPs ({len(C2_IPS)}) > MAX_DISTINCT_IPS_FOR_CONCENTRATION (3) -> concentrarea NU se va declansa")
    print(f"[*] Intrebare: regularitatea (beaconing) tot il prinde?")
    conn.close()


if __name__ == "__main__":
    generate()

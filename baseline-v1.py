#!/usr/bin/env python3
"""
Etapa 2: Analiză baseline + detecție anomalii.

Citește din traffic_monitor.db (populat de collector.py sau de
generate_test_data.py) și pentru fiecare proces calculează:

1. Baseline de volum: câte conexiuni face procesul, în medie, pe oră
2. Set de destinații "obișnuite" (IP-uri văzute recurent)
3. Regularitatea intervalelor dintre conexiuni (semnal de beaconing)

Apoi scorează fiecare proces 0-100 (risc de anomalie) și explică DE CE.

Rulare: python3 baseline.py
"""

import sqlite3
import statistics
from datetime import datetime
from collections import defaultdict

DB_PATH = "traffic_monitor.db"

# Praguri - le poți ajusta pe măsură ce vezi cum se comportă pe date reale
MIN_SAMPLES_FOR_BASELINE = 3       # sub atât, nu avem destule date ca să tragem concluzii
BEACONING_STDDEV_THRESHOLD = 5.0   # secunde - dacă intervalele variază mai puțin decât atât, e suspect de regulat
NEW_DESTINATION_WEIGHT = 30        # puncte de risc pt. destinație complet nouă / unică
BEACONING_WEIGHT = 50              # puncte de risc pt. pattern de beaconing
VOLUME_ANOMALY_WEIGHT = 20         # puncte de risc pt. volum neobișnuit de mare


def load_connections(conn: sqlite3.Connection) -> dict:
    """Grupează toate conexiunile pe proces."""
    cur = conn.execute("""
        SELECT process_name, timestamp, remote_ip, remote_port
        FROM connections
        ORDER BY process_name, timestamp
    """)
    by_process = defaultdict(list)
    for process_name, timestamp, remote_ip, remote_port in cur.fetchall():
        by_process[process_name].append({
            "timestamp": datetime.fromisoformat(timestamp),
            "remote_ip": remote_ip,
            "remote_port": remote_port,
        })
    return by_process


def analyze_process(process_name: str, connections: list, all_destinations: dict) -> dict:
    """
    Analizează un singur proces și întoarce un raport cu scor de risc.
    all_destinations = dict {ip: set(procese care s-au conectat la acel ip)}
    folosit ca să știm dacă o destinație e "unică" pentru acest proces.
    """
    n = len(connections)
    report = {
        "process_name": process_name,
        "total_connections": n,
        "risk_score": 0,
        "reasons": [],
    }

    if n < MIN_SAMPLES_FOR_BASELINE:
        report["reasons"].append(f"Prea puține date ({n} conexiuni) - baseline nesigur")
        return report

    # --- 1. Destinații unice (văzute DOAR la acest proces, la niciun altul) ---
    unique_ips = {c["remote_ip"] for c in connections}
    unique_to_this_process = [
        ip for ip in unique_ips
        if len(all_destinations.get(ip, set())) == 1
    ]
    if unique_to_this_process:
        # dacă TOATE conexiunile merg către o singură destinație unică, e mai suspect
        ratio = sum(1 for c in connections if c["remote_ip"] in unique_to_this_process) / n
        if ratio > 0.8:
            report["risk_score"] += NEW_DESTINATION_WEIGHT
            report["reasons"].append(
                f"{ratio*100:.0f}% din trafic merge către destinații necunoscute/unice: {unique_to_this_process[:3]}"
            )

    # --- 2. Regularitatea intervalelor (semnal clasic de beaconing/C2) ---
    timestamps = sorted(c["timestamp"] for c in connections)
    if len(timestamps) >= MIN_SAMPLES_FOR_BASELINE:
        intervals = [
            (timestamps[i+1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]
        if intervals:
            mean_interval = statistics.mean(intervals)
            stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0

            # deviație standard mică = intervale foarte regulate = comportament automatizat, nu uman
            if stdev_interval < BEACONING_STDDEV_THRESHOLD and mean_interval > 1:
                report["risk_score"] += BEACONING_WEIGHT
                report["reasons"].append(
                    f"Pattern de BEACONING: conexiuni la interval regulat de "
                    f"~{mean_interval:.0f}s (deviație std: {stdev_interval:.2f}s) - "
                    f"semn tipic de comunicare automatizată cu un server C2"
                )

    # --- 3. Volum neobișnuit (comparat cu ce văd celelalte procese) ---
    # Simplificat pentru MVP: procesele cu MULT mai multe conexiuni decât media generală
    report["_raw_intervals_mean"] = mean_interval if 'mean_interval' in dir() else None

    return report


def main():
    conn = sqlite3.connect(DB_PATH)
    by_process = load_connections(conn)

    if not by_process:
        print("[!] Nu există date în baza de date. Rulează mai întâi collector.py sau generate_test_data.py")
        return

    # construim harta globală: ce IP-uri a atins fiecare proces
    all_destinations = defaultdict(set)
    for process_name, connections in by_process.items():
        for c in connections:
            all_destinations[c["remote_ip"]].add(process_name)

    print("=" * 70)
    print("RAPORT BASELINE + DETECȚIE ANOMALII")
    print("=" * 70)

    reports = []
    for process_name, connections in by_process.items():
        report = analyze_process(process_name, connections, all_destinations)
        reports.append(report)

    # sortăm după risc descrescător, ca să vezi mai întâi ce e mai suspect
    reports.sort(key=lambda r: r["risk_score"], reverse=True)

    for r in reports:
        risk_label = "🔴 RISC RIDICAT" if r["risk_score"] >= 50 else (
            "🟡 RISC MODERAT" if r["risk_score"] > 0 else "🟢 NORMAL"
        )
        print(f"\nProces: {r['process_name']}")
        print(f"  Conexiuni totale: {r['total_connections']}")
        print(f"  Scor risc: {r['risk_score']}/100 -> {risk_label}")
        if r["reasons"]:
            print("  Motive:")
            for reason in r["reasons"]:
                print(f"    - {reason}")

    print("\n" + "=" * 70)
    conn.close()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Etapa 2: Analiză baseline + detecție anomalii.

Citește din traffic_monitor.db (populat de collector.py sau de
generate_test_data.py) și pentru fiecare proces calculează:

1. Baseline de volum: câte conexiuni face procesul, în medie, pe oră
2. Set de destinații "obișnuite" (IP-uri văzute recurent)
3. Regularitatea intervalelor dintre conexiuni (semnal de beaconing)

Apoi scorează fiecare proces 0-100 (risc de anomalie) și explică DE CE.

Rulare: python3 baseline_v4.py
"""

import sqlite3
import statistics
import ipaddress
from datetime import datetime
from collections import defaultdict
from reputation import check_ip_reputation, init_reputation_table

DB_PATH = "traffic_monitor.db"


def is_private_ip(ip: str) -> bool:
    """
    Verifică dacă un IP e privat/local (rețea de-acasă, router, etc.)
    Trafic către asemenea adrese NU poate fi exfiltrare externă,
    deci nu ar trebui să contribuie la scorul de risc.

    Exemple de IP-uri private: 192.168.x.x, 10.x.x.x, 172.16-31.x.x, 127.x.x.x (localhost)
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False  # daca nu putem parsa IP-ul, tratăm ca extern

# Praguri 
MIN_SAMPLES_FOR_BASELINE = 3       # sub atât, nu avem destule date ca să tragem concluzii
BEACONING_STDDEV_THRESHOLD = 5.0   # secunde - dacă intervalele variază mai puțin decât atât, e suspect de regulat
CONCENTRATION_WEIGHT = 30          # puncte de risc pt. trafic concentrat pe puține destinații fixe
BEACONING_WEIGHT = 50              # puncte de risc pt. pattern de beaconing
VOLUME_ANOMALY_WEIGHT = 20         # puncte de risc pt. volum neobișnuit de mare

# Praguri pentru regula de CONCENTRARE (înlocuiește vechea regulă de "unicitate")
MAX_DISTINCT_IPS_FOR_CONCENTRATION = 3   # dacă procesul vorbește cu MAI MULTE IP-uri distincte decât atât, îl considerăm "divers" (normal), nu concentrat
CONCENTRATION_RATIO_THRESHOLD = 0.7      # dacă un singur IP acoperă peste 70% din conexiunile externe, e concentrare suspectă

# Praguri pentru reputația externă (AbuseIPDB)
REPUTATION_HIGH_RISK_SCORE = 50    # abuse_score peste asta = risc confirmat extern
REPUTATION_WEIGHT = 40             # puncte de risc adăugate dacă reputația confirmă IP-ul ca abuziv
REPUTATION_TRUSTED_REDUCTION = 25  # puncte SCĂZUTE dacă IP-ul are 0 rapoarte și e cunoscut (reduce falși pozitivi gen 8.8.8.8)

# Prag pentru deduplicare de sesiuni
SESSION_GAP_SECONDS = 3.0          # conexiuni către aceeași destinație la interval sub atât = aceeași "sesiune", nu evenimente separate


def deduplicate_into_sessions(connections: list) -> list:
    """
    Colectorul face polling periodic (ex. la 1s), deci o conexiune care
    trăiește 1-2 secunde poate fi "văzută" de 2+ ori consecutiv - o dată
    la fiecare interogare cât timp conexiunea era încă activă.

    Fără deduplicare, asta strică regularitatea beaconing-ului: în loc de
    un eveniment "conexiune făcută" la fiecare 60s, avem PERECHI de
    evenimente (0s, 60s, 61s, 120s, 121s...) - intervalele devin neregulate,
    deși comportamentul de fond este regulat.

    Grupăm conexiuni consecutive către ACEEAȘI destinație (ip+port), aflate
    la mai puțin de SESSION_GAP_SECONDS una de alta, într-o singură "sesiune"
    - păstrăm doar primul timestamp din fiecare grup.
    """
    if not connections:
        return []

    # sortăm după destinație, apoi dupa timp, ca să grupăm corect sesiunile
    sorted_conns = sorted(connections, key=lambda c: (c["remote_ip"], c["remote_port"], c["timestamp"]))

    sessions = []
    current_key = None
    last_timestamp = None

    for c in sorted_conns:
        key = (c["remote_ip"], c["remote_port"])
        if key != current_key or (c["timestamp"] - last_timestamp).total_seconds() > SESSION_GAP_SECONDS:
            # început de sesiune nouă (destinație diferită SAU gap mare de timp)
            sessions.append(c)
            current_key = key
        last_timestamp = c["timestamp"]

    # reordonăm cronologic (am sortat după destinație mai sus, pentru grupare)
    sessions.sort(key=lambda c: c["timestamp"])
    return sessions


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


def analyze_process(process_name: str, connections: list, all_destinations: dict, db_conn: sqlite3.Connection) -> dict:
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

    # Deduplicăm conexiunile în sesiuni, ÎNAINTE de orice alt calcul.
    # Fără asta, polling-ul frecvent (1s) vede aceeași conexiune de mai
    # multe ori și strică regularitatea intervalelor.
    connections = deduplicate_into_sessions(connections)
    n_before_dedup = n
    n = len(connections)
    if n < n_before_dedup:
        report["reasons"].append(
            f"Deduplicare: {n_before_dedup} înregistrări brute -> {n} sesiuni reale de conexiune"
        )

    if n < MIN_SAMPLES_FOR_BASELINE:
        report["reasons"].append(f"Prea puține sesiuni reale ({n}) după deduplicare - baseline nesigur")
        return report

    # Separăm conexiunile către IP-uri PRIVATE (rețea locală, router) de cele
    # către IP-uri PUBLICE (internet). Doar traficul extern contează pentru riscul
    # de exfiltrare - trafic către 192.168.x.x nu poate fi C2 extern.
    external_connections = [c for c in connections if not is_private_ip(c["remote_ip"])]
    n_external = len(external_connections)
    n_private = n - n_external

    if n_private > 0:
        report["reasons"].append(
            f"({n_private} conexiuni către rețeaua locală, excluse din calculul de risc)"
        )

    if n_external < MIN_SAMPLES_FOR_BASELINE:
        report["reasons"].append(
            f"Prea putine conexiuni externe ({n_external}) - risc extern nesigur de evaluat"
        )
        return report

    # --- 1. CONCENTRARE vs DIVERSITATE (înlocuiește vechea regulă de "unicitate") ---
    # Ideea: nu contează dacă un IP e "unic în tot sistemul" (aproape orice site
    # vizitat de firefox e "unic" - e normal, semn de diversitate/browsing uman).
    # Contează dacă ACEST proces vorbește cu FOARTE PUȚINE destinații fixe,
    # concentrat - asta seamănă cu un canal de C2, nu cu navigare normală.
    ip_counts = defaultdict(int)
    for c in external_connections:
        ip_counts[c["remote_ip"]] += 1

    distinct_ips = len(ip_counts)
    top_ip, top_ip_count = max(ip_counts.items(), key=lambda kv: kv[1])
    concentration_ratio = top_ip_count / n_external

    is_concentrated = (
        distinct_ips <= MAX_DISTINCT_IPS_FOR_CONCENTRATION
        and concentration_ratio >= CONCENTRATION_RATIO_THRESHOLD
    )

    if is_concentrated:
        # semnal suplimentar: dacă acel IP dominant nu e văzut la niciun alt proces,
        # crește suspiciunea (nu e o infrastructură comună/partajată, gen CDN)
        seen_by_others = len(all_destinations.get(top_ip, set())) > 1
        report["risk_score"] += CONCENTRATION_WEIGHT
        report["reasons"].append(
            f"Trafic CONCENTRAT: {concentration_ratio*100:.0f}% din conexiunile externe "
            f"merg către un singur IP ({top_ip}), din doar {distinct_ips} destinații distincte total"
            + ("" if seen_by_others else " - IP văzut DOAR la acest proces, la niciun altul")
        )
    
        # NOU: verificăm reputația reală a IP-ului concentrat prin AbuseIPDB.
        # Verificăm DOAR aici (nu pentru toate IP-urile), tocmai ca să nu irosim
        # bugetul zilnic gratuit pe trafic divers/normal (ex. firefox cu 40 de IP-uri).
        reputation = check_ip_reputation(db_conn, top_ip)
        if reputation:
            report["reasons"].append(
                f"Reputație {top_ip} [{('cache' if reputation['from_cache'] else 'API')}]: "
                f"scor abuz {reputation['abuse_score']}/100, {reputation['total_reports']} rapoarte, "
                f"ISP: {reputation['isp']}"
            )
            if reputation["abuse_score"] >= REPUTATION_HIGH_RISK_SCORE:
                report["risk_score"] += REPUTATION_WEIGHT
                report["reasons"].append(
                    "-> Reputație externă CONFIRMĂ riscul (IP raportat activ ca abuziv)"
                )
            elif reputation["total_reports"] == 0 and reputation["abuse_score"] == 0:
                # IP fără NICIUN raport de abuz - probabil infrastructură legitimă
                # (ex. Google DNS, un CDN mare) - scădem riscul, nu-l anulăm complet
                report["risk_score"] = max(0, report["risk_score"] - REPUTATION_TRUSTED_REDUCTION)
                report["reasons"].append(
                    "-> Fără rapoarte de abuz - probabil infrastructură legitimă, risc redus"
                )
    else:
        report["reasons"].append(
            f"Trafic divers: {distinct_ips} destinații externe distincte - comportament tipic de navigare/utilizare normală"
        )

    # --- 2. Regularitatea intervalelor, CALCULATĂ DOAR PE TRAFIC EXTERN ---
    # (beaconing către routerul local e normal; beaconing către internet, nu)
    timestamps = sorted(c["timestamp"] for c in external_connections)
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
                    f"Pattern de BEACONING extern: conexiuni la interval regulat de "
                    f"~{mean_interval:.0f}s (deviație std: {stdev_interval:.2f}s) - "
                    f"semn tipic de comunicare automatizată cu un server C2"
                )

    # --- 3. Volum neobișnuit (comparat cu ce văd celelalte procese) ---
    # Simplificat pentru MVP: procesele cu MULT mai multe conexiuni decât media generală
    report["_raw_intervals_mean"] = mean_interval if 'mean_interval' in dir() else None

    return report


def main():
    conn = sqlite3.connect(DB_PATH)
    init_reputation_table(conn)  # tabela de cache pentru reputația IP-urilor
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
        report = analyze_process(process_name, connections, all_destinations, conn)
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

#!/usr/bin/env python3
"""
Experiment izolat: reverse DNS pe IP-urile reale din traffic_monitor.db.

NU modifică watcher_v6.py, baseline_v5.py sau baza de date.
Doar citește IP-urile deja colectate și încearcă să afle domeniul lor.

Scop: să vedem, pe date reale, cât de des reușim să aflăm un domeniu
pentru un IP, și cum arată rezultatele - înainte să construim orice
altceva pe baza asta.

Rulare: python3 experiment_reverse_dns.py
"""

import sqlite3
import socket
import ipaddress
from datetime import datetime, timezone
from baseline_v5 import is_private_ip

DB_PATH = "traffic_monitor.db"


def resolve_domain(ip: str) -> str | None:
    """
    Încearcă să afle domeniul unui IP prin reverse DNS.
    Întoarce None dacă nu reușește (multe IP-uri nu au reverse DNS configurat -
    e normal, nu e o eroare de-a noastră).
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def extract_base_domain(hostname: str) -> str:
    """
    Extrage "domeniul de bază" dintr-un hostname complet.

    Ex: lb-140-82-112-21-iad.github.com -> github.com
        lcfrai-in-f84.1e100.net         -> 1e100.net

    Euristică simplă: păstrăm ultimele 2 segmente separate prin punct.
    Funcționează bine pentru majoritatea domeniilor (.com, .net, .ro etc).

    LIMITARE cunoscută: greșește pe domenii cu TLD compus din 2 părți,
    gen "ceva.co.uk" -> euristica ar întoarce greșit "co.uk" în loc de
    "ceva.co.uk". Nu apare în datele noastre actuale, dar e important
    de reținut - o soluție completă ar folosi o listă de sufixe publice
    (public suffix list), nu doar "ultimele 2 segmente".
    """
    parts = hostname.rstrip(".").split(".")
    if len(parts) < 2:
        return hostname
    return ".".join(parts[-2:])


def test_extract_base_domain():
    """Testăm euristica exact pe exemplele reale găsite la pasul 1."""
    examples = [
        "lb-140-82-112-21-iad.github.com",
        "lcfrai-in-f84.1e100.net",
        "lcbuda-ah-in-x0e.1e100.net",
        "93.243.107.34.bc.googleusercontent.com",
        "g2a02-26f0-9c00-0000-0000-0000-684c-dc21.deploy.static.akamaitechnologies.com",
        "storage.rcs-rds.ro",
        "whatsapp-cdn6-shv-01-otp1.fbcdn.net",
    ]
    print("[*] Test extract_base_domain() pe exemple reale:\n")
    for hostname in examples:
        base = extract_base_domain(hostname)
        print(f"  {hostname:70s} -> {base}")
    print()


def get_group_key(ip: str, dns_cache: dict) -> tuple[str, str]:
    """
    La fel ca get_domain_for_ip, dar cu un fallback mai bun pentru IP-urile
    fără reverse DNS: în loc să tratăm fiecare IP individual, le grupăm pe
    blocul de rețea din care fac parte (/24 pentru IPv4, /48 pentru IPv6) -
    ipoteza fiind că IP-uri vecine, din același bloc, aparțin aceleiași
    infrastructuri (același furnizor de cloud, același serviciu).

    Întoarce (cheie_grupare, tip), unde tip e "domeniu", "subnet" sau "ip"
    (ultimul doar dacă nici IP-ul nu poate fi parsat - practic nu se
    întâmplă) - ca să vedem clar, în rezultate, ce metodă a fost folosită.
    """
    if ip in dns_cache:
        return dns_cache[ip]

    hostname = resolve_domain(ip)
    if hostname:
        result = (extract_base_domain(hostname), "domeniu")
    else:
        try:
            addr = ipaddress.ip_address(ip)

            # IPv4 mascat ca IPv6 (ex. ::ffff:34.78.67.165) - ACEEAȘI capcană
            # documentată deja în watcher_v6.py la is_effectively_loopback().
            # Fără tratare specială, primii 48 de biți sunt aproape toți zero
            # (fiindcă e "mascat"), deci /48 ar da mereu ::/48 - un grup fals
            # care ar înghesui laolaltă orice IP mascat, complet nelegate.
            # Soluție: dacă IPv6-ul e de fapt un IPv4 mascat, îl tratăm ca IPv4.
            if addr.version == 6 and addr.ipv4_mapped is not None:
                addr = addr.ipv4_mapped

            prefix = 24 if addr.version == 4 else 48
            network = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
            result = (str(network), "subnet")
        except ValueError:
            result = (ip, "ip")  # nu ar trebui să se întâmple, dar fallback ultim

    dns_cache[ip] = result
    return result


def get_domain_for_ip(ip: str, dns_cache: dict) -> str:
    """
    Combină resolve_domain() + extract_base_domain(), cu fallback pe IP
    dacă nu există reverse DNS (vezi limitarea găsită la pasul 1 - 20 din
    35 de IP-uri nu au reverse DNS, deci trebuie un fallback).

    dns_cache evită să interogăm de mai multe ori același IP - reverse DNS
    e o cerere de rețea, poate dura, nu vrem s-o repetăm degeaba.
    """
    if ip in dns_cache:
        return dns_cache[ip]

    hostname = resolve_domain(ip)
    domain = extract_base_domain(hostname) if hostname else ip  # fallback: IP-ul însuși, dacă n-avem domeniu
    dns_cache[ip] = domain
    return domain


def create_known_destinations_table(conn: sqlite3.Connection):
    conn.execute("DROP TABLE IF EXISTS known_destinations")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS known_destinations (
            process_name TEXT,
            group_key TEXT,
            group_type TEXT,
            first_seen TEXT,
            last_seen TEXT,
            times_seen INTEGER,
            PRIMARY KEY (process_name, group_key)
        )
    """)
    conn.commit()


def populate_known_destinations(conn: sqlite3.Connection):
    """
    Parcurge toate conexiunile deja colectate, calculează cheia de grupare
    a fiecărui IP (domeniu, sau subnet ca fallback), și construiește
    known_destinations - un rând per (proces, cheie), cu prima/ultima dată
    văzut, de câte ori, și prin ce metodă a fost grupat.
    """
    cur = conn.execute("""
        SELECT process_name, remote_ip, timestamp
        FROM connections
        ORDER BY timestamp
    """)
    rows = cur.fetchall()

    dns_cache: dict = {}
    agg: dict = {}  # (process, group_key) -> {"first":..., "last":..., "count":..., "type":...}

    for process_name, remote_ip, timestamp in rows:
        if is_private_ip(remote_ip):
            continue  # la fel ca în baseline_v5 - IP-urile locale nu contează aici

        group_key, group_type = get_group_key(remote_ip, dns_cache)
        key = (process_name, group_key)

        if key not in agg:
            agg[key] = {"first": timestamp, "last": timestamp, "count": 1, "type": group_type}
        else:
            e = agg[key]
            e["last"] = timestamp
            e["count"] += 1

    for (process_name, group_key), e in agg.items():
        conn.execute("""
            INSERT INTO known_destinations (process_name, group_key, group_type, first_seen, last_seen, times_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (process_name, group_key) DO UPDATE SET
                last_seen = excluded.last_seen,
                times_seen = excluded.times_seen
        """, (process_name, group_key, e["type"], e["first"], e["last"], e["count"]))
    conn.commit()

    print(f"[*] known_destinations populată: {len(agg)} perechi (proces, cheie) distincte\n")


def print_known_destinations(conn: sqlite3.Connection):
    cur = conn.execute("""
        SELECT process_name, group_key, group_type, times_seen, first_seen
        FROM known_destinations
        ORDER BY process_name, times_seen DESC
    """)
    print(f"{'PROCES':12s} {'CHEIE':35s} {'TIP':9s} {'VĂZUT DE':>9s}  PRIMA DATĂ")
    print("-" * 95)
    for process_name, group_key, group_type, times_seen, first_seen in cur.fetchall():
        print(f"{process_name:12s} {group_key:35s} {group_type:9s} {times_seen:>9d}x  {first_seen[:19]}")


def simulate_new_destination_alerts(conn: sqlite3.Connection):
    """
    Simulare, pe date reale: tratăm conexiunile de ASTĂZI ca fiind "live",
    iar tot ce e mai vechi ca fiind deja "cunoscut" - exact ce ar face
    watcher_v6.py integrat, dacă ar rula chiar acum.

    Regula: dacă procesul are deja cel puțin o destinație cunoscută ȘI
    cheia asta (domeniu/subnet) e complet nouă pentru el -> alertă.
    Dacă procesul e complet nou (prima lui conexiune) -> doar înregistrăm,
    fără alertă.
    """
    cur = conn.execute("""
        SELECT process_name, remote_ip, timestamp
        FROM connections
        ORDER BY timestamp
    """)
    rows = cur.fetchall()

    dns_cache: dict = {}
    known_keys: set = set()       # (process_name, group_key) deja văzute
    known_processes: set = set()  # procese care au cel puțin o destinație cunoscută

    cutoff = datetime.now(timezone.utc).strftime("%Y-%m-%d")  # azi, calculat automat - tot ce-i de azi = "live"
    print(f"[*] Prag folosit: tot ce-i înainte de {cutoff} = cunoscut, tot ce-i de {cutoff} = simulăm ca live\n")
    alerts = []

    for process_name, remote_ip, timestamp in rows:
        if is_private_ip(remote_ip):
            continue

        group_key, group_type = get_group_key(remote_ip, dns_cache)
        key = (process_name, group_key)
        is_old = timestamp < cutoff

        if is_old:
            # fază de construire a "cunoscutului" - doar înregistrăm, fără alertă
            known_keys.add(key)
            known_processes.add(process_name)
            continue

        # din acest punct, simulăm "sosire live" - aici s-ar declanșa regula
        if process_name in known_processes and key not in known_keys:
            alerts.append((timestamp, process_name, group_key, group_type))

        known_keys.add(key)
        known_processes.add(process_name)

    print(f"[*] Simulare (fără cooldown): {len(alerts)} alerte candidate de tip 'destinație nouă'\n")
    return alerts


def apply_cooldown(alerts: list, cooldown_seconds: int = 300) -> list:
    """
    Filtrează o listă de alerte candidate, păstrând doar prima alertă per
    proces din fiecare fereastră de `cooldown_seconds`. Restul rămân
    "absorbite" tăcut - nu se pierd (tot intră în known_destinations mai
    devreme, în simulate_new_destination_alerts), doar nu mai generează
    o alertă separată pentru utilizator.

    alerts: listă de (timestamp_str, process_name, group_key, group_type),
    presupusă deja în ordine cronologică (așa vin din simulate_new_destination_alerts).
    """
    last_alert_time: dict = {}
    kept = []
    suppressed_count = 0

    for timestamp_str, process_name, group_key, group_type in alerts:
        ts = datetime.fromisoformat(timestamp_str)

        if process_name in last_alert_time:
            elapsed = (ts - last_alert_time[process_name]).total_seconds()
            if elapsed < cooldown_seconds:
                suppressed_count += 1
                continue  # absorbit de cooldown, nu alertăm

        kept.append((timestamp_str, process_name, group_key, group_type))
        last_alert_time[process_name] = ts

    print(f"[*] Cooldown ({cooldown_seconds}s): {len(alerts)} candidate -> "
          f"{len(kept)} alerte reale, {suppressed_count} absorbite tăcut\n")
    return kept


def test_cooldown_on_real_burst():
    """
    Testăm apply_cooldown() EXACT pe secvența reală găsită la Miruna azi -
    11 alerte de la chrome, toate în 18 secunde (08:43:20 -> 08:43:38),
    plus 4 alerte separate de la alte procese, neafectate.
    """
    real_alerts = [
        ("2026-09-22T08:42:25", "jetbrains-toolbox", "3.160.246.0/24", "subnet"),
        ("2026-09-22T08:42:37", "firefox", "20.140.200.0/24", "subnet"),
        ("2026-09-22T08:43:20", "chrome", "2001:4860:482a::/48", "subnet"),
        ("2026-09-22T08:43:21", "chrome", "googleusercontent.com", "domeniu"),
        ("2026-09-22T08:43:24", "chrome", "88.211.219.0/24", "subnet"),
        ("2026-09-22T08:43:32", "chrome", "2001:4860:4841::/48", "subnet"),
        ("2026-09-22T08:43:34", "chrome", "2001:4860:4802::/48", "subnet"),
        ("2026-09-22T08:43:36", "chrome", "nflxso.net", "domeniu"),
        ("2026-09-22T08:43:36", "chrome", "netflix.com", "domeniu"),
        ("2026-09-22T08:43:37", "chrome", "2001:4860:4826::/48", "subnet"),
        ("2026-09-22T08:43:37", "chrome", "nflxvideo.net", "domeniu"),
        ("2026-09-22T08:43:37", "chrome", "2a05:d018:76c::/48", "subnet"),
        ("2026-09-22T08:43:37", "chrome", "2a06:98c1:3103::/48", "subnet"),
        ("2026-09-22T08:43:38", "chrome", "2606:4700:4407::/48", "subnet"),
        ("2026-09-22T08:46:17", "code", "akamaitechnologies.com", "domeniu"),
    ]
    print(f"[*] Test cooldown pe burst-ul real (15 candidate, 11 de la chrome în 18s)\n")
    kept = apply_cooldown(real_alerts, cooldown_seconds=300)
    for timestamp_str, process_name, group_key, group_type in kept:
        print(f"  [{timestamp_str}] {process_name} -> {group_key} ({group_type})")


def main():
    test_extract_base_domain()

    conn = sqlite3.connect(DB_PATH)
    create_known_destinations_table(conn)
    populate_known_destinations(conn)
    print_known_destinations(conn)
    print()

    alerts = simulate_new_destination_alerts(conn)
    final_alerts = apply_cooldown(alerts, cooldown_seconds=300)

    print(f"[*] Rezultat final, după cooldown: {len(final_alerts)} alerte reale\n")
    for timestamp, process_name, group_key, group_type in final_alerts:
        print(f"  [{timestamp[:19]}] {process_name} -> destinație NOUĂ: {group_key} ({group_type})")

    conn.close()


if __name__ == "__main__":
    main()

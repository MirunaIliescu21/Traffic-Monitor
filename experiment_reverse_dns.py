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
            prefix = 24 if addr.version == 4 else 48
            network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
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


def main():
    test_extract_base_domain()

    conn = sqlite3.connect(DB_PATH)
    create_known_destinations_table(conn)
    populate_known_destinations(conn)
    print_known_destinations(conn)
    conn.close()


if __name__ == "__main__":
    main()

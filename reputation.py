#!/usr/bin/env python3
"""
Verificare reputație IP prin AbuseIPDB, cu cache local.

De ce cache: AbuseIPDB free tier = 1000 verificări/zi. Fără cache,
am putea consuma tot bugetul verificând aceleași IP-uri (ex. 8.8.8.8)
de zeci de ori pe zi. Cu cache, fiecare IP e verificat o singură dată
la câteva zile (CACHE_TTL_DAYS).

Rulare de test: python3 reputation.py 8.8.8.8
"""

import os
import sqlite3
import requests
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()  # citește .env din folderul curent

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
API_URL = "https://api.abuseipdb.com/api/v2/check"
DB_PATH = "traffic_monitor.db"
CACHE_TTL_DAYS = 7  # după câte zile re-verificăm un IP deja cunoscut


def init_reputation_table(conn: sqlite3.Connection) -> None:
    """Tabelă separată de cache pentru reputația IP-urilor."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip TEXT PRIMARY KEY,
            abuse_score INTEGER,
            country_code TEXT,
            isp TEXT,
            total_reports INTEGER,
            checked_at TEXT NOT NULL
        )
    """)
    conn.commit()


def get_cached(conn: sqlite3.Connection, ip: str) -> dict | None:
    """Întoarce rezultatul din cache dacă există și nu a expirat."""
    cur = conn.execute(
        "SELECT abuse_score, country_code, isp, total_reports, checked_at FROM ip_reputation WHERE ip = ?",
        (ip,)
    )
    row = cur.fetchone()
    if not row:
        return None

    abuse_score, country_code, isp, total_reports, checked_at = row
    checked_time = datetime.fromisoformat(checked_at)
    if datetime.now(timezone.utc) - checked_time > timedelta(days=CACHE_TTL_DAYS):
        return None  # cache expirat, trebuie re-verificat

    return {
        "ip": ip,
        "abuse_score": abuse_score,
        "country_code": country_code,
        "isp": isp,
        "total_reports": total_reports,
        "from_cache": True,
    }


def query_abuseipdb(ip: str) -> dict | None:
    """Interoghează API-ul AbuseIPDB pentru un singur IP."""
    if not API_KEY:
        # Fără cheie API configurată - returnăm None silențios.
        # Nu mai afișăm mesaj la fiecare verificare, e zgomot inutil
        # dacă utilizatorul nu dorește să folosească această funcție.
        return None

    try:
        response = requests.get(
            API_URL,
            headers={"Key": API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        response.raise_for_status()
        data = response.json()["data"]
        return {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports", 0),
            "from_cache": False,
        }
    except requests.exceptions.RequestException as e:
        print(f"[!] Eroare la interogarea AbuseIPDB pentru {ip}: {e}")
        return None


def check_ip_reputation(conn: sqlite3.Connection, ip: str) -> dict | None:
    """
    Punctul de intrare principal: verifică reputația unui IP,
    folosind cache-ul dacă e disponibil, altfel interoghează API-ul
    și salvează rezultatul pentru data viitoare.
    """
    cached = get_cached(conn, ip)
    if cached:
        return cached

    result = query_abuseipdb(ip)
    if result is None:
        return None

    conn.execute("""
        INSERT INTO ip_reputation (ip, abuse_score, country_code, isp, total_reports, checked_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            abuse_score=excluded.abuse_score,
            country_code=excluded.country_code,
            isp=excluded.isp,
            total_reports=excluded.total_reports,
            checked_at=excluded.checked_at
    """, (
        result["ip"], result["abuse_score"], result["country_code"],
        result["isp"], result["total_reports"], datetime.now(timezone.utc).isoformat()
    ))
    conn.commit()

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Utilizare: python3 reputation.py <IP>")
        sys.exit(1)

    test_ip = sys.argv[1]
    conn = sqlite3.connect(DB_PATH)
    init_reputation_table(conn)

    result = check_ip_reputation(conn, test_ip)
    if result:
        source = "cache" if result["from_cache"] else "API (nou)"
        print(f"IP: {result['ip']} [{source}]")
        print(f"  Scor de abuz: {result['abuse_score']}/100")
        print(f"  Țară: {result['country_code']}")
        print(f"  ISP: {result['isp']}")
        print(f"  Total rapoarte: {result['total_reports']}")
    else:
        print("Nu s-a putut obține reputația (lipsă API key sau eroare de rețea).")

    conn.close()

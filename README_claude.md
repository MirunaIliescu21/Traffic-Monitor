# TrafficMonitor

Instrument local de monitorizare a traficului de rețea și detecție de anomalii,
inspirat de GlassWire. Proiect de licență — Facultatea de Automatică și
Calculatoare, UPB.

## Premisa

Accesul neautorizat generează întotdeauna trafic de rețea între sistemul
compromis și un sistem controlat de atacator, chiar și atunci când soluțiile
anti-malware nu detectează nimic. Monitorizând comportamentul de trafic al
fiecărui proces (cine vorbește cu cine, cât de des, cât de regulat) — nu
conținutul pachetelor — putem detecta o compromitere și după ce apărările
clasice au eșuat, reducând timpul cât un atacator stă nedetectat în sistem.

Nu e un instrument de prevenție. E un instrument de **detecție**.

## Arhitectură

```
collector.py    -> colectează periodic conexiunile active proces<->IP, în SQLite
baseline_v5.py  -> analizează istoricul, scorează fiecare proces 0-100
watcher_v6.py   -> rulează continuu: colectare + alertare live + conexiuni inbound
dashboard.py    -> interfață web Flask (doar citește din DB)
traffic_monitor.db -> SQLite, partajată de toate componentele
```

Scorul de risc din `baseline_v5.py` se bazează pe două semnale:

- **Concentrare**: procesul vorbește cu foarte puține IP-uri fixe (≤3),
  concentrat pe unul singur (≥70% din trafic) — semn de canal C2
- **Beaconing**: intervalele dintre conexiuni sunt suspect de regulate
  (coeficient de variație < 15%) — semn de comunicare automatizată

`watcher_v6.py` mai detectează separat și **conexiuni inbound** neașteptate
(potențiale scanări/atacuri primite), și un mecanism de **whitelist
comportamental** (vezi secțiunea dedicată mai jos).

## Cum rulează

Trei procese separate, în terminale diferite, pe aceeași `traffic_monitor.db`:

```bash
# Terminal 1 — colectare + analiză de risc + alertare live
sudo python3 watcher_v6.py

# Terminal 2 — dashboard web (fără sudo, doar citește)
python3 dashboard.py
```

Apoi deschide browserul la `http://localhost:5000`.

`collector.py` există separat pentru cazul în care vrei doar colectare brută,
fără analiză live — nu se rulează de obicei în paralel cu `watcher_v6.py`,
care face deja ambele.

### Interfața web

- **Procese active (24h)** — cine vorbește cu cine, câte conexiuni, câte
  IP-uri distincte
- **Jurnal alerte** — istoricul alertelor de risc
- **Conexiuni primite (inbound)** — potențiale scanări/atacuri către mașină
- **Conexiuni noi observate** — combinații (proces, IP) văzute prima dată

Se auto-reîmprospătează la 5 secunde.

### Probleme cunoscute

- Rularea cu `sudo` e necesară ca `psutil` să vadă toate conexiunile (nu doar
  ale userului curent), dar notificările desktop (`notify-send`) pot eșua cu
  `ServiceUnknown: org.freedesktop.Notifications`, pentru că root nu are
  acces direct la sesiunea D-Bus grafică a userului. Fără `sudo` dispare
  eroarea, dar se pierde vizibilitatea pe procesele altor useri.
- Detecția de beaconing e sensibilă la o singură întrerupere în pattern: un
  gol izolat în intervalele altfel regulate poate crește suficient
  coeficientul de variație încât să scape de sub prag, chiar dacă restul
  traficului e clar regulat.

## Whitelist comportamental (destinații cunoscute per proces)

Pe lângă concentrare/beaconing, `watcher_v6.py` ține minte, per proces,
ce destinații sunt "normale" pentru el, ca să deosebească o conexiune nouă
banală (IP nou pentru un serviciu deja cunoscut) de o schimbare reală de
comportament (proces cunoscut, infrastructură complet nouă).

Lanțul de decizie, per conexiune ieșită:

```
IP -> reverse DNS (domeniu) -> dacă lipsește, subnet /24 (IPv4) sau /48 (IPv6)
   -> compară cu known_destinations (proces, cheie)
   -> dacă procesul e deja cunoscut ȘI cheia e complet nouă -> candidat de alertă
   -> cooldown per proces (5 min) -> alertă reală ("[NOU-COMPORTAMENT]")
```

- Reverse DNS reușește pe doar ~43% din IP-urile externe observate — restul
  cad pe fallback-ul de subnet, care ajută mult pe infrastructuri compacte
  (Google, Cloudflare pe IPv6), dar aproape deloc pe cloud-uri mari cu
  alocare împrăștiată (Azure)
- IP-urile IPv4-mascate-ca-IPv6 (`::ffff:x.x.x.x`) primesc tratare specială
  (a doua oară că acest format cauzează o capcană în proiect, după
  `is_effectively_loopback()`)
- Cooldown-ul per proces reduce zgomotul de burst (testat pe un caz real:
  15 candidate -> 4 alerte reale, când Chrome a deschis Netflix și a atins
  11 destinații Google/Netflix noi în 18 secunde)
- La prima pornire, `known_destinations` se populează automat din tot
  istoricul deja colectat (backfill), ca să nu pornească de la zero
- Notificarea veche `[info] Conexiune nouă` rămâne neschimbată, complet
  aditiv — `[NOU-COMPORTAMENT]` e un semnal separat, mai rar și mai relevant

## Stadiu curent

- Prototip funcțional, testat pe date reale capturate (Firefox, Chrome,
  Cursor, VS Code, curl simulat, nc) și pe VM-uri Kali/Metasploitable2
- 26 de teste automate (`test_baseline.py`, `test_watcher.py`), toate trec
- Integrarea AbuseIPDB (reputație externă de IP) a fost eliminată — nu se
  potrivea cu premisa centrală axată pe comportament, nu pe liste externe
- Whitelist comportamental (domeniu/subnet + cooldown), validat pe date
  reale, integrat în `watcher_v6.py` și în `experiment_reverse_dns.py`
  (scriptul izolat folosit pentru dezvoltare incrementală, păstrat ca
  documentație a procesului)

## Următorii pași posibili

- Rafinare ASN (în loc de subnet /24) pentru gruparea cloud-urilor mari,
  cu o bază de date externă (ex. MaxMind GeoLite2-ASN)
- Listă de sufixe publice (public suffix list) pentru `extract_base_domain`,
  ca să trateze corect domenii tip `ceva.co.uk`
- UI în dashboard pentru gestionarea manuală a whitelist-ului

## Mediu de testare

- Ubuntu 24.04 ca host
- VirtualBox: VM-uri Kali Linux (atacator) și Metasploitable2 (țintă
  vulnerabilă) pentru scenarii de test controlate

# TrafficMonitor

Instrument local de monitorizare a traficului de rețea și detecție de anomalii,
inspirat de GlassWire. Proiect de licență — Facultatea de Automatică și
Calculatoare, UPB — care evoluează spre un produs pentru utilizatori
non-tehnici (clienți Infologica Silverline).

## Premisa

Accesul neautorizat generează întotdeauna trafic de rețea între sistemul
compromis și un sistem controlat de atacator, chiar și atunci când soluțiile
anti-malware nu detectează nimic. Monitorizând comportamentul de trafic al
fiecărui proces (cine vorbește cu cine, cât de des, cât de regulat) — nu
conținutul pachetelor — putem detecta o compromitere și după ce apărările
clasice au eșuat, reducând timpul cât un atacator stă nedetectat în sistem.

Nu e un instrument de prevenție. E un instrument de **detecție**.

## Arhitectură

| Fișier | Rol |
|---|---|
| `watcher_v6.py` | Rulează continuu: colectează conexiunile, alertează live, detectează conexiuni primite și comportament nou |
| `baseline_v5.py` | Analiza de risc: scor 0-100 per proces (concentrare + beaconing) |
| `dashboard.py` | Interfață web Flask: arată starea și primește deciziile utilizatorului |
| `destination_status.py` | Stările destinațiilor (de verificat / normal / suspect) și istoricul deciziilor |
| `companies.py` | Traduce domenii și blocuri de IP-uri în nume de companii („Google”, „Microsoft”) |
| `retention.py` | Șterge datele vechi din bază |
| `collector.py` | Colectare brută, fără analiză (nu se rulează în paralel cu watcher-ul) |
| `traffic_monitor.db` | SQLite, partajată de toate componentele (nu se versionează) |

## Cum rulează

Două procese, în terminale separate, pe aceeași `traffic_monitor.db`:

```bash
# Terminal 1 — colectare + alertare live
python3 watcher_v6.py

# Terminal 2 — dashboard web
python3 dashboard.py
```

Apoi deschide `http://localhost:5000`. Rulează un singur watcher odată.

Fără `sudo`, notificările desktop funcționează, dar `psutil` vede doar
procesele utilizatorului curent. Cu `sudo` se văd toate procesele, dar
notificările eșuează (vezi „Limitări”).

## Interfața web

- **De verificat** — destinații noi pentru programe cunoscute, cu butoanele
  „E normal” și „Nu recunosc”, în limbaj simplu („chrome s-a conectat pentru
  prima dată la Google”)
- **Deciziile tale** și **Istoric decizii** — ce ai hotărât și când, cu
  posibilitatea de a anula o decizie
- **Procese active (24h)**, **Jurnal alerte**, **Conexiuni primite
  (inbound)**, **Conexiuni noi observate**

Se reîmprospătează la 5 secunde. Deciziile se aplică în ~1 secundă, fără
repornirea watcher-ului.

## Cum funcționează detecția

### 1. Scor de risc (`baseline_v5.py`)

- **Concentrare**: procesul vorbește cu foarte puține IP-uri fixe (≤3),
  concentrat pe unul singur (≥70% din trafic) — semn de canal C2
- **Beaconing**: intervalele dintre conexiuni sunt suspect de regulate
  (coeficient de variație < 15%) — semn de comunicare automatizată
- Activitatea e împărțită în sesiuni (goluri > 10 min), iar regularitatea se
  analizează pe cea mai mare, ca un gol de zile să nu ascundă un beacon real

### 2. Conexiuni primite (inbound)

Conexiunile către porturile pe care mașina ascultă generează alertă imediată,
inclusiv de la IP-uri private (un atacator din aceeași rețea locală).

### 3. Comportament nou, cu decizia utilizatorului

Pentru fiecare conexiune ieșită, destinația primește o **entitate**: compania,
dacă o cunoaștem (Google, Microsoft, Amazon...), altfel domeniul sau blocul de
IP-uri (/24 pentru IPv4, /48 pentru IPv6).

```
conexiune ieșită -> entitate (companie / domeniu / bloc IP)
   -> proces cunoscut ȘI entitate nouă pentru el -> notificare + „de verificat”
   -> cooldown per proces (5 min) limitează notificările, nu și lista
```

Fiecare destinație are una din trei stări:

| Stare | Ce face |
|---|---|
| **de verificat** | Apare în dashboard; nu mai alertează; nu devine „normală” niciodată automat |
| **normal** („E normal”) | Nu mai alertează |
| **suspect** („Nu recunosc”) | Orice conexiune nouă către ea alertează critic, ignorând cooldown-ul |

Deciziile se iau la nivel de companie: „E normal” la Google acoperă toate
blocurile Google.

## Grupare pe companii (`companies.py`)

Două liste scrise de mână: domenii (`1e100.net` → Google) și intervale de
IP-uri publice cunoscute (acoperă adresele fără reverse DNS). Pe datele reale
de dezvoltare, 96 din 97 de destinații distincte au fost identificate;
restul rămân „rețea neidentificată”. Aplicația nu ghicește niciodată o
companie.

Ca să adaugi o mapare: editezi `DOMAIN_COMPANIES`, `_PREFIXES_BY_COMPANY` și,
pentru o companie nouă, `COMPANIES` (cu o descriere), apoi rulezi
`python3 -m pytest -q test_companies.py` și repornești watcher-ul. Rândurile
existente din „De verificat” se contopesc automat pe noua companie.

## Retenția datelor (`retention.py`)

Rulează automat la pornirea watcher-ului și la fiecare 6 ore.

- `connections`: 14 zile
- `inbound_events`: 90 de zile
- tot restul (destinații cunoscute, decizii, istoric) se păstrează

În `connections` se scrie doar o conexiune **nouă** (care nu era deschisă la
citirea precedentă), nu fiecare conexiune la fiecare secundă (ritmul vechi:
~275 MB/zi).

Ștergerea oprește creșterea bazei, dar nu micșorează fișierul. Pentru asta,
cu watcher-ul și dashboard-ul oprite: `python3 retention.py --vacuum`.
`python3 retention.py --dry-run` arată ce s-ar șterge, fără să șteargă.

## Securitatea dashboard-ului

Dashboard-ul ascultă doar pe `127.0.0.1` și nu are autentificare. Fiindcă
poate scrie decizii, acceptă cereri doar dacă `Host` și `Origin` sunt cele
ale dashboard-ului și corpul e JSON (un site deschis în alt tab nu poate
apăsa „E normal” în numele utilizatorului). Textele care vin din rețea
(nume de host, procese) sunt escapate înainte să ajungă în pagină.

## Teste

```bash
python3 -m pytest -q
```

108 teste: baseline, watcher, stările destinațiilor, dashboard, retenție,
companii (inclusiv pe o listă reală de destinații, `tests_real_keys.txt`) și
scrierea conexiunilor noi. `conftest.py` izolează jurnalul de alerte, ca
testele să nu scrie în `alerts.log`-ul real.

## Limitări cunoscute

- **Grupare pe companii vs. detecție:** un program care vorbește deja cu o
  companie mare de cloud (Amazon, Cloudflare) nu primește alertă de
  „comportament nou” pentru o adresă nouă a aceleiași companii. Un server
  rău intenționat găzduit acolo scapă de această regulă; concentrarea și
  beaconing-ul rămân active.
- **Liste manuale:** `companies.py` e incomplet și trebuie întreținut. Pe alte
  mașini acoperirea va fi mai mică decât pe datele de dezvoltare.
- **Rularea cu `sudo`:** necesară ca `psutil` să vadă toate conexiunile, dar
  `notify-send` poate eșua cu `ServiceUnknown` (root nu are acces la sesiunea
  D-Bus a utilizatorului).
- **Beaconing:** regularitatea se analizează doar pe sesiunea cea mai mare;
  una mai mică și mai veche e ignorată.
- **Fără autentificare** în dashboard (doar acces local).
- **Contoare:** după trecerea la „doar conexiuni noi”, contoarele din
  dashboard (24h) scad treptat pe măsură ce rândurile vechi, scrise la
  secundă, ies din fereastră.

## Stadiu curent

- Prototip funcțional, testat pe date reale (Firefox, Chrome, Cursor,
  VS Code, curl simulat, nc) și pe VM-uri Kali/Metasploitable2
- Alerta „de verificat” și deciziile utilizatorului funcționează cap-coadă
- Gruparea pe companii a redus lista „de verificat” de la 29 la 10 pe datele
  reale

## Următorii pași

- Rularea ca serviciu (un singur proces, pornit odată cu sistemul;
  rezolvă conflictul `sudo` vs. notificări)
- Test pe 2-3 mașini: câte alerte false pe zi, ce procent din destinații e
  identificat pe date pe care lista nu le-a văzut
- Bază ASN pentru identificarea oricărei adrese (ex. iptoasn.com, domeniu
  public — verificat termenii licenței înainte de distribuire)
- Listă de sufixe publice pentru `extract_base_domain` (domenii tip
  `ceva.co.uk`)
- Fișier local de mapări (`companies_local.json`), fără editarea codului
- Versiuni pentru Windows și macOS

## Mediu de testare

- Ubuntu 24.04 ca host
- VirtualBox: VM-uri Kali Linux (atacator) și Metasploitable2 (țintă
  vulnerabilă) pentru scenarii de test controlate
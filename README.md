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
(potențiale scanări/atacuri primite).

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

## Stadiu curent

- Prototip funcțional, testat pe date reale capturate (Firefox, Chrome,
  Cursor, VS Code, curl simulat, nc) și pe VM-uri Kali/Metasploitable2
- 26 de teste automate (`test_baseline.py`, `test_watcher.py`), toate trec
- Integrarea AbuseIPDB (reputație externă de IP) a fost eliminată — nu se
  potrivea cu premisa centrală axată pe comportament, nu pe liste externe

## Următorul pas: whitelist / baseline de comportament normal

Momentan, "conexiune nouă" înseamnă doar "nu apărea în `notified_pairs`" —
o memorie brută, fără nicio noțiune de comportament normal per proces.
Următorul pas e o fază de învățare care stabilește, per proces, care sunt
destinațiile obișnuite, astfel încât alerta reală să fie "acest proces iese
din comportamentul lui stabilit", nu doar "n-am mai văzut asta niciodată" —
reducând falsele pozitive și apropiind sistemul de premisa lui inițială.

## experiment_reverse_dns_1.py - rezolvarea destinațiilor (domeniu → subnet → IP)

Am construit un mecanism de **grupare a destinațiilor externe** care încearcă,
în ordine, trei metode, fiecare fiind un fallback pentru cea anterioară.

Prima metodă, **reverse DNS** (`resolve_domain`), întreabă sistemul cui aparține un IP 
și, dacă răspunde, `extract_base_domain` reduce hostname-ul complet la domeniul lui
de bază (`lb-140-82-112-21-iad.github.com` → `github.com`) - aceasta e categoria **"domeniu"**,
cea mai de încredere, pentru că grupează corect indiferent cât de mult rotește furnizorul
IP-urile din spate (confirmat pe date reale: `github.com`, `1e100.net`, `amazonaws.com`, `fbcdn.net` etc.).

Când reverse DNS eșuează și am văzut empiric că se întâmplă la aproape 60% din IP-urile externe,
mai ales pe IPv6, intervine a doua metodă, categoria **"subnet"**: grupăm IP-ul după blocul lui 
de rețea (`/24` pentru IPv4, `/48` pentru IPv6), pe ipoteza că adrese vecine aparțin aceleiași infrastructuri.
Testat pe date reale, fallback-ul ăsta a redus numărul de perechi distincte de la 63 la 47 - ajută consistent 
pe infrastructuri regionale/compacte (Google, Cloudflare pe IPv6), dar nu face nimic pentru furnizori mari de 
cloud cu alocare împrăștiată (Azure, la `code`, a rămas cu IP-uri complet separate chiar și după grupare). 

Categoria a treia, **"ip"**, e fallback-ul ultim, IP-ul e păstrat ca atare, fără nicio grupare și practic nu
se mai declanșează acum, decât dacă adresa nici măcar nu poate fi parsată. 

Pe parcurs am descoperit și reparat un bug real: IP-urile IPv4-mascate-ca-IPv6 (`::ffff:34.78.67.165`) 
confundau euristica de `/48`, producând un grup fals `::/48` care ar fi înghesuit laolaltă orice astfel de adresă, 
indiferent de destinația reală - a doua oară când acest format cauzează o problemă subtilă în proiect,
după cea deja documentată în `is_effectively_loopback()`.

### Ce am deja rezolvat, în watcher_v6.py:

`notified_pairs `— un (proces, IP) o dată notificat nu se mai repetă niciodată (evită să retrimită la infinit aceeași pereche)
`risk_alert_state` — pentru alertele de risc (concentrare/beaconing), nu retrimite dacă datele n-au adus nimic nou
 (asta a fost regresia cu curl retrimis de 3 ori, reparată și testată)


 Cu plăcere — hai să punem cap la cap toată ziua de azi, de la motivul inițial până la ce rulează acum, live, pe mașina ta.

### watcher_v6.py + experimnet_reverse_dns_2.py => watrcher_v6_eperiment.py

Sistemul de dinainte trata la fel orice conexiune nouă: `firefox` care vizitează un site nou și un proces necunoscut care vorbește brusc cu un IP nou arătau identic — "n-am mai văzut asta". Ideea whitelist-ului era să înlocuiască semnalul ăsta brut cu unul calitativ diferit: **"acest proces are un comportament stabilit, iar asta îl încalcă"** — mai aproape de premisa centrală a tezei (trafic anormal = semn de compromitere), care presupune că știi ce e normal pentru procesul respectiv.

## Ce am construit, bucată cu bucată, testat izolat înainte de a atinge codul principal

1. **Reverse DNS** (`resolve_domain`) — am aflat empiric că doar ~43% din IP-urile externe au reverse DNS configurat. Nu e o eroare de-a noastră, e o limitare reală a internetului, bună de documentat.

2. **Extragere domeniu de bază** (`extract_base_domain`) — `lb-140-82-112-21-iad.github.com` → `github.com`. Testat pe exemple reale din datele tale, cu o limitare cunoscută și asumată (domenii tip `.co.uk`).

3. **Fallback pe subnet** pentru IP-urile fără reverse DNS — grupare pe `/24` (IPv4) / `/48` (IPv6). Am descoperit empiric că ajută mult pe infrastructuri compacte (Google, Cloudflare pe IPv6), dar aproape deloc pe cloud-uri mari și împrăștiate (Azure) — o limitare reală, nu un bug.

4. **Un bug real prins pe parcurs**: IP-uri IPv4-mascate-ca-IPv6 (`::ffff:34.78.67.165`) produceau un grup fals `::/48`. Reparat, folosind `addr.ipv4_mapped` — a doua oară când formatul ăsta cauzează o problemă subtilă în proiect (prima fiind la `is_effectively_loopback()`).

5. **Regula de bază**: proces deja cunoscut + destinație (domeniu/subnet) niciodată văzută → alertă. Proces complet nou → doar înregistrăm, fără alertă (n-avem încă "normal" de comparat).

6. **Cooldown** — testat direct pe burst-ul tău real cu Chrome (11 alerte în 18 secunde, din cauza deschiderii Netflix): 5 minute de cooldown per proces au redus 15 candidate la 4 alerte reale, fără să piardă nimic (tot intră în `known_destinations`, doar nu mai spamează).

## Integrarea în `watcher_v6.py`

- **2 tabele noi**: `known_destinations`, `whitelist_alert_state` (cooldown persistat între reporniri, ca `risk_alert_state`)
- **Backfill automat**, o singură dată, din istoricul deja colectat — ca să nu pornești de la zero deși ai luni de date
- **Alertă nouă `[NOU-COMPORTAMENT]`**, complet aditivă — vechea `[info] Conexiune nouă` n-a fost atinsă, rulează în paralel

## Confirmarea finală

Ai validat totul de **două ori independent**: o rulare continuă normală, și un reset complet (ștergere `known_destinations`/`notified_pairs`/stări, păstrând istoricul `connections`) — în ambele cazuri, backfill-ul a recuperat corect toate datele (74 de perechi), iar regula a extras un număr mic, plauzibil de alerte reale dintr-un volum mare de zgomot brut (`[info]`).

Practic, ai acum un lanț complet și testat: **IP brut → domeniu/subnet → istoric per proces → cooldown → alertă**, plus dovezi empirice (nu doar teorie) pentru fiecare decizie de design — exact genul de material solid pentru discuția cu profesorul.

## Mediu de testare

- Ubuntu 24.04 ca host
- VirtualBox: VM-uri Kali Linux (atacator) și Metasploitable2 (țintă
  vulnerabilă) pentru scenarii de test controlate

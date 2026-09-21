# baseline-v1.py
(base) miruna@pink:~/Documents/INFOLOGICA/Licenta/traffic-monitor$ python3 baseline.py
======================================================================
RAPORT BASELINE + DETECȚIE ANOMALII
======================================================================

Proces: MathWorksServiceHost
  Conexiuni totale: 56
  Scor risc: 80/100 -> 🔴 RISC RIDICAT
  Motive:
    - 100% din trafic merge către destinații necunoscute/unice: ['3.160.246.22']
    - Pattern de BEACONING: conexiuni la interval regulat de ~5s (deviație std: 0.00s) - semn tipic de comunicare automatizată cu un server C2

Proces: NetworkManager
  Conexiuni totale: 117
  Scor risc: 80/100 -> 🔴 RISC RIDICAT
  Motive:
    - 100% din trafic merge către destinații necunoscute/unice: ['192.168.3.1']
    - Pattern de BEACONING: conexiuni la interval regulat de ~5s (deviație std: 0.00s) - semn tipic de comunicare automatizată cu un server C2

Proces: curl
  Conexiuni totale: 3
  Scor risc: 30/100 -> 🟡 RISC MODERAT
  Motive:
    - 100% din trafic merge către destinații necunoscute/unice: ['203.0.113.77']

Proces: firefox
  Conexiuni totale: 2169
  Scor risc: 30/100 -> 🟡 RISC MODERAT
  Motive:
    - 100% din trafic merge către destinații necunoscute/unice: ['172.217.23.35', '192.178.25.163', '216.58.205.129']

Proces: systemd-resolved
  Conexiuni totale: 1
  Scor risc: 0/100 -> 🟢 NORMAL
  Motive:
    - Prea puține date (1 conexiuni) - baseline nesigur

======================================================================

Chiar dacă pare puțin contraintuitiv la prima vedere, acesta e un rezultat foarte valoros pentru licență, pentru că demonstrează exact limitele unui algoritm simplist — și tocmai procesul pe care l-ai "atacat" cu adevărat (`curl`) a ieșit cu risc mai mic decât procese complet legitime.

## Ce s-a întâmplat, explicat

**`NetworkManager` → 192.168.3.1** — asta e routerul tău local (IP privat, clasa 192.168.x.x). NetworkManager verifică periodic conexiunea la router la fiecare 5 secunde — comportament normal, sănătos, dar algoritmul nostru îl vede ca "beaconing suspect" pentru că nu știe să facă diferența între **IP local/privat** (rețeaua ta de-acasă) și **IP public/extern** (unde ar fi un server C2 real).

**`MathWorksServiceHost`** — probabil MATLAB, care verifică licența la un server extern la fiecare 5s — tot legitim, dar din perspectiva algoritmului arată identic cu un malware care "sună acasă".

**`curl` cu scor doar 30** — pentru că a avut doar 3 conexiuni în fereastra de test (probabil bucla n-a rulat destul de mult, sau `curl` a eșuat rapid din cauza timeout-ului de 2s și n-a apucat să facă suficiente cicluri de 60s ca să vedem regularitatea clar). Cu doar 3 eșantioane, algoritmul n-are destule date ca să fie sigur de pattern.

## Rafinarea concretă — ce schimbăm și de ce

Adăugăm **două reguli noi**, esențiale pentru un sistem real:

1. **Excludem IP-urile private/locale** (192.168.x.x, 10.x.x.x, 172.16-31.x.x) din calculul de risc — trafic către rețeaua ta locală nu e niciodată exfiltrare externă.
2. **Distingem "beaconing legitim" de "beaconing suspect"** — dacă destinația e un IP public dar recunoscut/stabil (verificat manual sau whitelist), scade riscul. Dar dacă destinația e un IP public, complet nou, nemaivăzut de niciun alt proces, chiar cu interval regulat, rămâne suspect.

Hai să implementez asta acum, cu comentarii clare, ca să vezi exact ce s-a schimbat față de varianta anterioară.Acum modific funcția principală de analiză, ca să filtreze IP-urile private înainte de a calcula riscul:Acum testez rapid schimbarea pe datele tale, ca să confirm că `NetworkManager` dispare din lista de risc, iar restul rămâne coerent:Am prins un bug interesant, chiar din propriul meu test — `203.0.113.77` (IP-ul pe care l-am folosit ca exemplu de "atacator" în teste) e de fapt un IP rezervat special pentru documentație (TEST-NET-3), iar Python îl clasifică drept "privat" din greșeală în contextul nostru. Hai să verific exact ce se întâmplă.Confirmat — problema e că `203.0.113.0/24` e un bloc rezervat pentru documentație (TEST-NET-3), și biblioteca Python `ipaddress` îl marchează greșit ca `is_private=True` în acest context. E o particularitate a IP-ului de test pe care l-am ales eu pentru exemplu, **nu o problemă reală a algoritmului** — un IP public real (ex. un server C2 adevărat pe internet) nu ar avea această problemă.

Hai să confirmăm asta cu un IP public normal, ca să fim siguri că logica de bază e corectă:Confirmat — logica e corectă pentru IP-uri reale (8.8.8.8, 1.1.1.1, orice server real de pe internet). Problema a fost doar în alegerea mea de IP de test (203.0.113.77 e special rezervat pentru documentație și cade din greșeală în aceeași categorie cu IP-urile private din perspectiva bibliotecii Python).

## Ce înseamnă asta practic pentru tine

Pe **datele tale reale**, pe care le-ai rulat mai devreme cu `curl` către `203.0.113.77`, algoritmul rafinat ar fi eliminat din greșeală acel proces din categoria de risc — dar doar din cauza IP-ului de test folosit, nu din cauza unui bug real în logică.

**Pentru testarea viitoare**, ca să eviți această capcană, folosește alt IP de test — de exemplu, un IP public real dar controlat (poți folosi IP-ul propriu al VM-ului Kali în rețeaua locală ar fi privat și el; cel mai simplu, un serviciu public real ca `curl -m 2 http://93.184.216.34` — IP vechi al example.com, sau orice IP public real pe care ai voie să-l accesezi).

Rulează din nou testul pe laptopul tău, cu regulile rafinate (fișierul `baseline.py` de mai sus e deja actualizat local aici, pregătesc versiunea nouă pentru tine):## Rezumat ce am schimbat și de ce (pentru licență, notează-ți asta)

1. **Am adăugat funcția `is_private_ip()`** — folosește biblioteca standard Python `ipaddress`, care verifică dacă un IP e din intervalele rezervate pentru rețele locale (RFC 1918: `192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`) sau loopback.

2. **Filtrăm conexiunile private ÎNAINTE de a calcula riscul** — asta a eliminat falsul pozitiv de la `NetworkManager` (care doar verifica routerul local la fiecare 5s, comportament complet normal).

3. **Am descoperit un bug secundar interesant**: IP-ul de test pe care l-am ales (`203.0.113.77`, bloc TEST-NET-3) e clasificat greșit ca "privat" de librăria Python — asta arată de ce **testarea cu IP-uri de test artificiale poate ascunde probleme reale**. Pentru licență, chiar poți menționa asta ca o lecție despre pericolele testării cu date sintetice vs. date/adrese reale.

## Ce faci acum, pe laptop

1. Descarci `baseline.py` (versiunea nouă) și-l pui peste cel vechi în folder
2. Repetăm testul, dar de data asta cu un IP public real ca țintă a "atacului" simulat — de exemplu:
```bash
while true; do
  curl -s -m 2 http://93.184.216.34/ > /dev/null 2>&1
  sleep 60
done
```
3. Rulezi din nou `python3 baseline.py` (pe baza de date deja existentă, nu mai trebuie collector din nou dacă ai încă date din testul anterior — dar dacă vrei date proaspete, repetăm collector.py + curl simultan)

# baseline-v2.py
Progres real, dar cu o observație importantă: **fix-ul cu IP-uri private a funcționat perfect** — `NetworkManager` a scăzut de la 80 la 0, exact cum voiam. Dar **problema de fond nu e complet rezolvată** — vezi că `firefox`, `code` (VS Code) și `systemd-resolved` au acum risc 30, din exact același motiv structural ca înainte.

## De ce apar aceste falși pozitivi noi

Regula "% din trafic merge către destinații unice" are o slăbiciune conceptuală: **aproape orice aplicație care vizitează multe site-uri diferite va avea "destinații unice"**, pentru că fiecare CDN/server web are IP propriu, nefolosit de alt proces. Deci regula confundă:

- **Diversitate normală** (firefox vizitează 50 de IP-uri diferite = comportament de browsing uman) 
- **Concentrare suspectă** (un proces vorbește *doar* cu 1-2 IP-uri fixe, repetat = tipar de C2)

`systemd-resolved → 8.8.8.8` e cel mai clar exemplu — DNS-ul Google, extrem de comun și legitim, dar apare "unic" pentru că doar acel proces face cereri DNS.

## Rafinarea corectă: măsurăm concentrarea, nu unicitatea

Trebuie să inversăm logica: nu contează dacă IP-ul e "unic în sistem", contează dacă **procesul însuși** vorbește cu puține destinații fixe (concentrare) sau cu multe destinații diferite (diversitate = semn de normalitate). Combinat cu regularitatea (beaconing), asta elimină falșii pozitivi de tip browser/DNS.

# baseline-v3.py

Acum înlocuiesc regula #1 (unicitate) cu o regulă de **concentrare** — măsurăm dacă traficul e concentrat pe puține IP-uri fixe (suspect) sau răspândit pe multe destinații diferite (normal, gen browsing)

Acum testez pe un scenariu care combină: proces cu trafic divers (gen firefox, multe IP-uri) + proces concentrat pe un singur IP (gen beaconing)

Exact rezultatul dorit: **firefox e acum 0/100 (normal)**, pentru că regula recunoaște diversitatea de 40 destinații ca fiind comportament sănătos. `suspicious_proc` rămâne corect la 80/100. `systemd-resolved` rămâne la 30 (nu 0) — și e corect din perspectiva algoritmului brut, fără cunoștințe externe: DNS spre un singur IP e concentrare reală, doar că 8.8.8.8 e cunoscut ca legitim, ceea ce ne duce direct spre pasul următor.

## Rezumat rafinare (notează pentru licență — asta e progresul de la v1 la v3)

| Versiune | Regulă | Problemă |
|---|---|---|
| v1 | "% conexiuni către IP-uri unice în tot sistemul" | Firefox/apt = fals pozitiv (orice site vizitat e "unic") |
| v2 | v1 + excludere IP-uri private | A rezolvat NetworkManager, dar firefox/code/DNS rămân fals pozitive |
| v3 (acum) | **Concentrare** (puține IP-uri fixe, % mare pe unul singur) în loc de unicitate | Firefox → 0 (corect). systemd-resolved → 30 (parțial corect, lipsește whitelist pt. servicii cunoscute) |

`systemd-resolved → 8.8.8.8` cu 30/100 e exact motivul pentru care avem nevoie de pasul următor: **AbuseIPDB** îți dă reputația reală a unui IP, ca să distingi "concentrat pe un IP necunoscut/suspect" de "concentrat pe un IP cunoscut/major" (Google DNS, Cloudflare etc.).


# QUESTION: In practica reala cum invatam niste adrese IP ? cum facem corect diferenta dintre u IP nou periculos si un IP nou care nu prezinta niciun risc? explica mi putin cum reusim sa evoluam cu ceea ce incercam sa implementam aici

Excelentă întrebare — asta e chiar nucleul problemei de cercetare pentru licența ta, pentru că nu există un răspuns simplu de tip "IP-ul X e rău". Hai să trec prin toate abordările folosite în practică, de la simplu la avansat.
1. Nu poți ști dacă un IP e "rău" doar din el însuși

Un atacator poate folosi orice IP — inclusiv servere cloud legitime (AWS, Azure, Google Cloud), exact ca aplicațiile normale. Deci identitatea IP-ului, singură, nu e suficientă. De aceea, industria combină mai multe surse de semnal, nu doar una.
2. Sursele reale folosite în practică

a) Perioada de învățare (baseline learning period) — asta faci deja. Timp de X zile (tipic 7-14 zile în produse comerciale), sistemul presupune că tot traficul e "normal" și construiește un profil. După asta, orice se abate de la profil e suspect. Presupunerea (riscantă, dar practică) e că un sistem nou instalat nu e deja compromis.

b) Threat intelligence feeds (reputație externă) — baze de date publice/comerciale cu IP-uri raportate ca malițioase:

    AbuseIPDB (gratuit, API simplu) — comunitate raportează IP-uri suspecte
    VirusTotal — agregă mai multe surse de reputație
    Spamhaus, AlienVault OTX — liste de C2 cunoscute, botnet-uri

Practic, când vezi un IP nou, îl verifici într-un asemenea feed: dacă are rapoarte de abuz recente, crește riscul automat.

c) Analiza infrastructurii, nu doar a IP-ului:

    ASN (Autonomous System Number) — cui aparține IP-ul? Un IP dintr-un ASN de hosting "bulletproof" (cunoscut că găzduiește des activitate malițioasă) e mai suspect decât unul dintr-un ASN Google/Microsoft/Cloudflare
    Vârsta domeniului/certificatului — infrastructură C2 nou înregistrată (domeniu creat acum 2 zile) e un semnal clasic
    Geolocație neașteptată — dacă utilizatorul e în România și brusc un proces se conectează la un IP dintr-o țară fără nicio legătură cu aplicațiile instalate, crește suspiciunea (dar NU e determinant singur — poți avea legitim CDN-uri globale)

d) Comportamentul conexiunii, nu doar destinația (ce ai construit deja, e valoros!):

    Regularitate perfectă a intervalelor (beaconing)
    Volum mic, constant (comenzi C2, nu transfer de date normal)
    Fără rezolvare DNS vizibilă înainte de conexiune (multe unelte malițioase conectează direct la IP, ocolind DNS, ca să evite unele filtre)

3. Cum "evoluează" sistemul — abordarea corectă pentru licența ta

Aici e ideea centrală de cercetare, exact ce ai numit "baseline adaptiv":

Whitelist automat, construit din observație — dacă un proces se conectează la același IP/domeniu, constant, de-a lungul multor zile, fără alte semnale de risc (nu e beaconing perfect regulat, are variație umană), sistemul "învață" că acea destinație e de încredere pentru acel proces. Exact ca la Firefox — la început fiecare IP e "nou", dar dacă vezi aceleași domenii Google/Mozilla apărând zilnic, devin parte din baseline normal.

Scădere de risc în timp (decay) — o destinație nou-apărută primește risc mai mare inițial; dacă persistă fără alte semnale roșii, riscul ei scade progresiv. E ideea de EWMA pe care am discutat-o la început.

Corelare cu integritatea binarului — dacă procesul care face conexiunea e un binar cunoscut, semnat digital, neschimbat (hash identic cu ce a fost la instalare), riscul scade. Dacă procesul rulează dintr-un loc neobișnuit (/tmp/, cum am simulat eu în exemplul cu suspicious_proc) sau hash-ul s-a schimbat recent, riscul crește mult.
4. Ce fac produsele comerciale mature (Darktrace, CrowdStrike etc.)

Folosesc modele de ML (adesea ansambluri de arbori de decizie sau rețele neuronale) antrenate pe milioane de rețele reale, nu doar rețeaua unui singur utilizator — beneficiază de "învățare colectivă": ce e normal la mii de organizații similare. Un prototip de licență nu poate replica asta (nu ai acces la date la scară), dar poți cita limitarea explicit: sistemul tău funcționează local, per-mașină, fără telemetrie colectivă, ceea ce înseamnă un timp de învățare mai lung și mai puține date de comparație.
Recomandare concretă pentru pasul următor în cod

## Următorul pas: AbuseIPDB

Ca să integrăm:
1. Creezi cont gratuit pe **abuseipdb.com** → obții un API key (1000 verificări/zi gratis)
2. Adaug o funcție care verifică doar IP-urile flagate ca "concentrate" (nu toate, ca să nu consumăm bugetul degeaba)
3. Cache local (SQLite), ca să nu verificăm de două ori același IP

Vrei să mergi acum să-ți faci cont pe AbuseIPDB și-mi dai API key-ul (îl păstrezi tu, doar îl pui într-un fișier de config local, nu mi-l trimiți mie), sau vrei să-ți arăt întâi codul complet ca să-l ai gata cand faci contul?

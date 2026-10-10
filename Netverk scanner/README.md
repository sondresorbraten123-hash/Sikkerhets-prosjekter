# Nettverkskanner (`main.py`)

Et raskt og asynkront nettverksskanningsverktøy skrevet i Python som skanner etter åpne porter på en gitt IP-adresse eller nettadresse. Verktøyet prøver også å fange "bannere" fra åpne porter for å gi mer informasjon om tjenestene som kjører (spesielt for HTTP/HTTPS).

## Funksjoner
- **Rask portskanning**: Bruker `concurrent.futures.ThreadPoolExecutor` for å skanne mange porter samtidig (opptil 500 tråder).
- **Banner Grabbing**: Prøver automatisk å hente banner/tjenesteinformasjon for åpne porter.
- **HTTP/HTTPS gjenkjenning**: Sender en HTTP GET-forespørsel for port 80 og 443 for å lettere fange opp nettserver-informasjon.
- **Oppsummering**: Viser en tydelig oppsummering over hvor mange porter som er åpne og lukkede, sammen med banner-info.

## Krav
- Python 3
- Ingen eksterne biblioteker er nødvendig (bruker kun innebygde `socket` og `concurrent.futures`).

## Bruk
Kjør skriptet i terminalen:

```bash
python main.py
```

Du vil da bli bedt om å oppgi:
1. IP-adresse eller nettadresse du vil skanne.
2. Startport (f.eks. 1).
3. Sluttport (f.eks. 1000).

### Eksempel:
```text
Skriv inn en IP/nettadresse for testing: scanme.nmap.org
Skriv inn port du vil starte fra, til og med siste port du vil skanne
Skriv inn start port: 1
Skriv inn siste port: 100
Skanner netverk...
[+] Port: 22 er åpen, Banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
[+] Port: 80 er åpen, Banner: HTTP/1.1 200 OK
Skanning ferdig 
Antall åpne porter: 2 
Antall lukkede porter: 98
[+] Åpne porter:
[+] Port: 22, Banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
[+] Port: 80, Banner: HTTP/1.1 200 OK
```

> **Advarsel:** Kun bruk dette verktøyet på nettverk og systemer du eier, eller der du har eksplisitt tillatelse til å utføre skanning (som f.eks. `scanme.nmap.org`).

# CSOC Telemetry Pipeline

## Bakgrunn og formål

Prosjektet ble oprettet hovedsaklig som del av en jobbsøknad for å vise dedikasjon og forståelse.

I et Security Operations Center (SOC) genereres det enorme mengder ustrukturerte logger. For å kunne oppdage angrep (som brute-force eller uautorisert tilgang) må rådata vaskes og struktureres.

Dette prosjektet simulerer en mini-SIEM datapipeline som leser rå autentiserings- og systemlogger, trekker ut sikkerhetshendelser ved hjelp av Regex, og lagrer dem i en lokal SQLite-database for videre analyse.

> **Obs** Prosjektet er også utviklet og testet på linux ved bruk av bash/fish kommandolinje, det er ikke testet på andre operativsystemer.
> **Obs** Verktøyet er laget som en demo for å forstå konseptet og teknologien bak denne typen utvikling, ikke for bruk med andre logger. Hvis loggene du har tenkt å bruke ikke er satt sammen på akkurat samme måte som loggene som blir generert, kommer ikke dette programmet til å fungere korrekt. Dette er bare et prosjekt ment for læring og forståelse.

## Nøkkelfunksjonalitet

* **Log Parsing & Normalisering:** Bruker Regex for å trekke ut tidsstempel, IP-adresser, brukernavn og hendelsestype fra ustrukturerte loggfiler.
* **Strukturert lagring:** Oppretter og populerer en SQLite-database automatisk.
* **Automatisk z-score analyse** Det er opprettet en algoritme for å analysere data med z-score og bruk av sql.
* **API for henting av IP info** Det blir brukt ip-api.com for å hente informasjon som land, isp og organisasjon fra IP addressen. Dette er også oprettet med cache i databasen for å hindre unødvendige API oppslag.
* **SHA256 hashing og indeksering** Dette er integrert for å hindre duplisering og gjøre søk i databasen raskere.

## Teknologier

* **Språk:** Python 3 med bare standard libraries
* **Database:** SQLite 3

## Hvordan kjøre prosjektet

1. Klon repositoriet og naviger til mappen:

   ```bash
   cd csoc-telemetry-pipeline
   ```

2. Kjør deretter main.py filen med kommandoen:

    ```bash
    python3 main.py --demo
    ```

* Du kan også bruke --help for en liste over kommandoer du kan bruke med programmet.

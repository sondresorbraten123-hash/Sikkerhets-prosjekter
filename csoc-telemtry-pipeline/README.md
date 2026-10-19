# CSOC Telemetry Pipeline

## Bakgrunn og formål

Prosjektet ble oprettet hovedsaklig som del av en jobbsøknad for å vise dedikasjon og forståelse.

I et Security Operations Center (SOC) genereres det enorme mengder ustrukturerte logger. For å kunne oppdage angrep (som brute-force eller uautorisert tilgang) må rådata vaskes og struktureres.

Dette prosjektet simulerer en mini-SIEM datapipeline som leser rå autentiserings- og systemlogger, trekker ut sikkerhetshendelser ved hjelp av Regex, og lagrer dem i en lokal SQLite-database for videre analyse.

> **Obs** Prosjektet er også utviklet og testet på linux ved bruk av bash/fish kommandolinje, det er ikke testet på andre operativsystemer.

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

> **Obs** Dette prosjektet ble opprettet med en spesifikk loggstruktur. Hvis ikke loggene du har tenkt å teste følger nøyaktig samme struktur som testloggene kommer ikke regex til å fange opp riktige data. Regex mønsteret kan tilpasses din egen loggstruktur, men dette må gjøres selv.

1. Klon repositoriet og naviger til mappen:

   ```bash
   cd csoc-telemetry-pipeline
   ```

2. Kjør deretter main.py filen med kommandoen:

    ```bash
    python3 main.py --demo
    ```

* Du kan også bruke --help for en liste over kommandoer du kan bruke med programmet.

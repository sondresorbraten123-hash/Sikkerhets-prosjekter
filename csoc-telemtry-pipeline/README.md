# CSOC Telemetry Pipeline

## Bakgrunn og formål

Prosjektet ble oprettet hovedsaklig som del av en jobbsøknad for å vise dedikasjon og forståelse.

I et Security Operations Center (SOC) genereres det enorme mengder ustrukturerte logger. For å kunne oppdage angrep (som brute-force eller uautorisert tilgang) må rådata vaskes og struktureres.

Dette prosjektet simulerer en mini-SIEM datapipeline som leser rå autentiserings- og systemlogger, trekker ut sikkerhetshendelser ved hjelp av Regex, og lagrer dem i en lokal SQLite-database for videre analyse.

> **Obs** Prosjektet er også utviklet og testet på linux ved bruk av bash/fish kommandolinje, det er ikke testet på andre operativsystemer.

## Nøkkelfunksjonalitet

* **Log Parsing & Normalisering:** Bruker Regex for å trekke ut tidsstempel, IP-adresser, brukernavn og hendelsestype fra ustrukturerte loggfiler.
* **Strukturert lagring:** Oppretter og populerer en SQLite-database automatisk.
* **Sikkerhetsanalyse via SQL:** Gjør det enkelt å kjøre spørringer for å finne anomalier, som f.eks. IP-adresser med flest feilede innloggingsforsøk.

## Teknologier

* **Språk:** Python 3
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

> **Advarsel** Verktøyet er laget som en demo for å forstå konseptet og teknologien bak denne typen utvikling, ikke for bruk med andre logger. Hvis loggene du har tenkt å bruke ikke er satt sammen på akkurat samme måte som loggene som blir generert, kommer ikke dette programmet til å fungere korrekt. Dette er bare et prosjekt ment for læring og forståelse.

# CSOC CTI Integrator

## Bakgrunn og formål

Prosjektet ble oprettet hovedsaklig som del av en jobbsøknad for å vise dedikasjon og forståelse.

Dette prosjektet simulerer en analyse av brannmurtrafikk, ved å ta inn informasjon fra en kilde som sporer malware og banktrojanerer, programmet er ment å ta inn loggen for å se på de og korrelere mot informasjonen den får fra kilden.

> **Obs:** Prosjektet er også utviklet og testet på linux ved bruk av bash/fish kommandolinje, det er ikke testet på andre operativsystemer.

## Nøkkelfunksjonalitet

* **Automatisk innhenting av trusselfeed:** Henter aktive C2-servere (Indicators of Compromise) fra Abuse.ch Feodo Tracker i JSON-format og oppdaterer databasen automatisk.
* **Overvåkning av API-helse:** Måler responstid i millisekunder og loggfører HTTP-statuskode i en egen tabell for enklere feilsøking hvis datakilden skulle være nede.
* **Korrelasjon og hvitelisting:** Bruker Regex til å lese brannmurlogger, filtrerer bort godkjente IP-adresser via en hviteliste for å unngå falske positiver, og kryssjekker trafikken mot kjente C2-servere.
* **Algoritmisk risikoscoring (0–100):** Regner ut en risikoscore for hver alarm basert på skadevarefamilie, mengde bytes overført (skiller mellom vanlig C2 heartbeat og mulig data-eksfiltrering) og tidsforfall (hvor lenge det er siden trusselen sist var aktiv).
* **Strukturert SQLite-lagring og indeksering:** Bruker `ON CONFLICT DO UPDATE` for effektiv oppdatering av trusler, samt `UNIQUE`-regler og indekser for å hindre duplikate alarmer og gi raske oppslag.

## Teknologier

* **Språk:** Python 3 med bare standard libraries
* **Database:** SQLite 3

## Hvordan kjøre prosjektet

> **Obs:** Programmet ble oprettet med testlogger som simulerer NetFlow, hvis du har logger som har lik struktur som dette, kan du bruke dine egne logger med programmet. Eller du kan endre regex mønsteret manuelt.

1. Klon repositoriet og naviger til mappen:

   ```bash
   cd csoc-cti-integrator
   ```

2. Kjør deretter main.py filen med kommandoen for testing:

    ```bash
    python3 main.py --demo
    ```

* Du kan også bruke --help for en liste over kommandoer du kan bruke med programmet.

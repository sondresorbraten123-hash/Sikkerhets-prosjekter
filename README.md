# Sikkerhetsprosjekter

Dette repoet inneholder forskjellige sikkerhetsrelaterte verktøy og skript jeg har laget.

Prosjektene er laget med noe hjelp fra AI for å finne ut av hvordan jeg starter prosjektene.
Alt av kode er skrevet manuelt, og jeg har har kommentert alt mens jeg utviklet det for å vise forståelse og læring gjennom utviklingen.

## 1. [Phishing Triage](./Phishing%20Triage/)

Et verktøy for å gjøre en rask førstehåndsvurdering av potensielt skadelige lenker ved hjelp av VirusTotal API. Nøytraliserer farlige lenker i output for å forhindre uhell.

## 2. [Nettverkskanner](./Netverk%20scanner/)

Et raskt, multi-trådet nettverksskanningsverktøy i Python som skanner porter og forsøker å fange bannere fra tjenestene som kjører.

## 3. [CSOC Telemetry Pipeline](./csoc-telemtry-pipeline/)

Et prosjekt for skanning av ssh logger, med demo modus for testing av programmet. Programmet sjekker loggene for Brute Force angrep og statistiske avvik via z-score algoritme.
# Sikkerhetsprosjekter

Velkommen til Github porteføljen min, hvor jeg viser frem noen av sikkerhetsverktøyene jeg har utviklet.
Formålet med dette repoet er å kombinere teoretisk forståelse for konsepter med faktiske utviklingsteknologier som jeg har lært. Samtidig hjelper dette meg å forstå konseptene på en dypere måte ved å utvikle ekte løsninger.

## 1. [CSOC Telemetry Pipeline](./csoc-telemtry-pipeline/)

Et prosjekt for skanning av ssh logger, med demo modus for testing av programmet. Programmet sjekker loggene for Brute Force angrep og statistiske avvik via z-score algoritme. Programmet bruker Regex for normalisering og gruppering og beriker IPen gjennom ip-api.com.

## 2. [CSOC CTI Integrator](./csoc-cti-integrator/)

Dette prosjektet tar inn ekstern info fra en kilde som sporer banktrojanere og lignende, og kryssjekker dette mot simulerte brannmurlogger. Den analyserer loggene og legger infoen inn i en SQLite database. Den bruker Regex for normalisering og skaffer informasjon via abuse.ch.

## 3. [Phishing Triage](./Phishing%20Triage/)

Et verktøy for å gjøre en rask førstehåndsvurdering av potensielt skadelige lenker ved hjelp av VirusTotal API. Nøytraliserer farlige lenker i output for å forhindre uhell.

## 4. [Nettverkskanner](./Netverk%20scanner/)

Et raskt, multi-trådet nettverksskanningsverktøy i Python som skanner porter og forsøker å fange bannere fra tjenestene som kjører.

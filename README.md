# Forskjellige typer sikkerhetsverktøy jeg har laget

## 1. Phishing Triage (`Phishing triage.py`)

Et enkelt og effektivt verktøy for å gjøre en rask førstehåndsvurdering (triage) av potensielt skadelige lenker (phishing). Skriptet bruker VirusTotal API (v3) for å sjekke om en gitt URL allerede er flagget som farlig av sikkerhetsleverandører.

For å forhindre at man ved et uhell trykker på en farlig lenke under analysen, "nøytraliserer" verktøyet automatisk URL-en i terminal-outputen (for eksempel ved å bytte ut `https://` med `hxxps://`).

### Krav

- Python 3
- `requests`-biblioteket (installeres via `pip install requests`)
- En VirusTotal API-nøkkel

### Oppsett

Før du kjører skriptet, må du legge inn VirusTotal API-nøkkelen din som en miljøvariabel.

Åpne terminalen og kjør:

```bash
export VT_API_KEY='din_api_nøkkel_her'
```

### Bruk

Kjør skriptet med Python:

```bash
python "Phishing triage.py"
```

Skriptet vil be deg om å taste inn URL-en du ønsker å sjekke:

```text
[*] Please enter a URL: https://example.com
```

**Eksempel på output (Farlig URL):**

```text
[-] 2 sikkerhetsmotorer flagger hxxps://google.com som farlig!
```

**Eksempel på output (Ingen funn):**

```text
[+] Ingen umiddelbare treff for hxxps://trygg-side.no.
```

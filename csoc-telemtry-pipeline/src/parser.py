import hashlib
import re
from typing import Dict, Optional

# Sorterer linjer i loggen for at de skal være sortert og klare for lagring i db

# Grupperer de forskjellige delene av logglinjene ved hjelp av regex
log_monster = re.compile(
    # Gruppe for tidsstempelet
    r"^(?P<tidsstempel>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+"

    # Gruppe for servernavnet, her "nb-srv-01"
    r"(?P<servernavn>[\w\-]+)\s+"

    # Gruppe for tjenesten, her "sshd" og hopper over pid så den ikke blir tatt med noen steder
    r"(?P<tjeneste>\w+)\[\d+\]:\s+"

    # Gruppe for status, (Feilet/akseptert) og gruppe for metode (publickey/passord eller andre mulige måter) 
    r"(?P<status>Akseptert|Feilet)\s+(?P<metode>\S+)\s+for\s+"

    # For å spise opp ordene ukjent og bruker om dette står i logg linjen
    # Denne blir ikke brukt til noe, den er bare for å forsikre lesing av bruker i neste gruppe
    r"(?:(?:ukjent\s+)?bruker\s+)?"

    # Gruppe for brukernavnet og hopper over ordet fra
    r"(?P<brukernavn>[\w\-]+)\s+fra\s+"

    # Gruppe for IP der koblingen kommer fra og gruppe for port nr
    r"(?P<fra_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+(?P<port>\d+)"
)


# Funksjon for å ta inn en linje fra loggen og "parse" den gjenom for å gruppere den i mønsteret lagd over
# Og gi tilbake en dictionary gruppert i dette mønsteret eller None om det ikke er en gyldig linje
def parse_log_linje(ra_log_linje: str) -> Optional[dict[str, str]]:
    # Fjerner linjeskift
    linje = ra_log_linje.strip()

    # Sjekker om linjen er tom med en gang
    if not linje:
        return None

    # Bruker regex mønsteret jeg lagde over til å gruppere linjen
    passer_monster = log_monster.search(linje)

    # Sjekker om linjen passer mønsteret
    if not passer_monster:
        return None
    
    # legger den grupperte linjen i en dictionary
    data = passer_monster.groupdict()

    # normaliserer statusen til Common Event Format
    hendelses_type = "AUTH_SUCCESS" if data["status"] == "Akseptert" else "AUTH_FAILED"

    # Sjekker at det ikke er dupliserte logger, siden db ikke vil lagre duplikater
    # ved å gjøre om hele linjen til bytes og regne ut en sha256 hash på den
    hendelses_hash = hashlib.sha256(linje.encode("utf-8")).hexdigest()

    return{
        "hendelses_hash": hendelses_hash,
        "tidsstempel": data["tidsstempel"],
        "servernavn": data["servernavn"],
        "tjeneste": data["tjeneste"],
        "hendelses_type": hendelses_type,
        "auth_metode": data["metode"],
        "brukernavn": data["brukernavn"],
        "fra_ip": data["fra_ip"],
        "hel_log_linje": linje,
    }

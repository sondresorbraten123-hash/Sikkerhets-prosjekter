from datetime import datetime
import re
from typing import Any, Dict
from src.database import CTIDatabase

# Regex for å lese brannmurloggen
brannmur_monster = re.compile(
    # Fanger opp tidsstempel
    r"^(?P<tidsstempel>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+"
    # spiser opp allow og tcp og mellomrommene
    r"ALLOW\s+TCP\s+"
    # tar inn den interne IPen
    r"(?P<intern_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+->\s+"
    # Tar inn ekstern IP og Port
    r"(?P<ekstern_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<port>\d+)\s+"
    # Fanger opp bytes sendt
    r"bytes=(?P<bytes>\d+)"
)

# Klasse for korrelasjon/analyse og deteksjon
class KorrelasjonsMotor:

    # Konstruktør som kobler til db
    def __init__(self, db: CTIDatabase):
        self.db = db

    # Funksjon for beregning av risiko scoren fra 0-100 med tidsforfall
    def beregn_risiko_score(self, ioc_info: Dict[str, Any], bytes_sendt: int) -> int:

        # Sjekker skadevare familien mot kjente høyrisiko familier
        familie = ioc_info["type_skadevare"].lower()
        hoyrisiko_familier = {
            "qakbot", "qbot", "dridex", "emotet", "pikabot", "trickbot", "cobalt strike",
        }
        base_score = 75 if familie in hoyrisiko_familier else 60

        # Sjekker mengde bytes overført, høyt volum indikerer aktiv data-eksfil
        if bytes_sendt >= 1000000:
            byte_tilegg = 20
        elif bytes_sendt >= 50000:
            byte_tilegg = 10
        else:
            byte_tilegg = 0
        
        # Sjekker alder på skadevare, eldre gir mindre risiko_score
        try:
            sist_sett_dato = datetime.strptime(ioc_info["sist_sett"], "%Y-%m-%d")
            dager_siden = max(0, (datetime.now() - sist_sett_dato).days)
            alder_fradrag = min(30, int(dager_siden * 1.5))
        except ValueError:
            alder_fradrag = 0
        
        # sjekker om den står som aktiv eller ikke
        status_tilegg = 5 if ioc_info.get("status") == "online" else 0

        total_score = (
            base_score + byte_tilegg + status_tilegg - alder_fradrag
        )
        return max(0, min(100,total_score))

    # Sjekker brannmur loggen mot info_henter.py og legger til ny alarm hvis det er ny alarm
    # returnerer statistikk via en dict
    def analyser_trafikk(self, logg_sti: str) -> Dict[str, int]:
        alle_ioc = self.db.get_ioc_dict()
        hviteliste = self.db.get_hviteliste()

        statistikk = {
            "lest_linjer": 0,
            "hviteliste_ignorert": 0,
            "nye_alarmer": 0,
        }

        # Tar ut info etter bruk av regex mønsteret og legger til statistikk
        loggfil = open(logg_sti, "r", encoding = "utf-8")
        for ra_linje in loggfil:
            treff = brannmur_monster.search(ra_linje.strip())
            if not treff:
                continue

            statistikk["lest_linjer"] += 1
            data = treff.groupdict()
            intern_ip = data["intern_ip"]
            ekstern_ip = data["ekstern_ip"]
            port = int(data["port"])
            bytes_sendt = int(data["bytes"])

            # Sjekker om IPen er hvitelistet
            if (ekstern_ip in hviteliste or intern_ip in hviteliste):
                statistikk["hviteliste_ignorert"] += 1
                continue

            # Sjekker om IPen ligger i db for IOC og lager en ny alarm til c2_alarmer hvis den er der
            if ekstern_ip in alle_ioc:
                ioc_info = alle_ioc[ekstern_ip]
                score = self.beregn_risiko_score(ioc_info, bytes_sendt)

                if score >= 85:
                    alvorlighetsgrad = "KRITISK"
                elif score >= 65:
                    alvorlighetsgrad = "HØY"
                else:
                    alvorlighetsgrad = "MEDIUM"

                atferd = (
                    "Mulig data eksfil"
                    if bytes_sendt >= 1000000
                    else "C2 Beacon / Heartbeat"
                )
                beskrivelse = (
                    f"{atferd} oppdaget fra {intern_ip} mot kjent {ioc_info['type_skadevare']} C2-server"
                    f" ({ekstern_ip}:{port}). Sendt: {bytes_sendt} bytes. IOC sist aktiv: {ioc_info['sist_sett']}."
                )
                c2_alarm = {
                    "tidsstempel": data["tidsstempel"],
                    "intern_ip": intern_ip,
                    "ekstern_ip": ekstern_ip,
                    "ekstern_port": port,
                    "type_skadevare": ioc_info["type_skadevare"],
                    "bytes_sendt": bytes_sendt,
                    "risiko_score": score,
                    "alvorlighetsgrad": alvorlighetsgrad,
                    "beskrivelse": beskrivelse,
                }

                if self.db.insert_c2(c2_alarm):
                    statistikk["nye_alarmer"] += 1
        loggfil.close()

        return statistikk
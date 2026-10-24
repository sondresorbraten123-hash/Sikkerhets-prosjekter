from datetime import datetime, timedelta
import json
import time
from typing import Any, Dict, List
import urllib.request
from src.database import CTIDatabase

# Dette er klassen for å hente trussel info fra en offisiell trussel feed som sporer forskjellige typer malware
class TrusselInfoHenter:
    # definerer URLen til feeden vi bruker for å hente trusseldata
    feodo_url = ("https://feodotracker.abuse.ch/downloads/ipblocklist.json")

    # Konstruktør for å sette opp database tilkoblingen
    def __init__(self, db: CTIDatabase):
        self.db = db

    # Oppdaterer den lokale db med trussel info, måler responstid, normaliserer dataen og
    # returnerer hvor mange nye som ble lagret
    def oppdater_trussel_info(self) -> int:
        start_tid = time.perf_counter()
        kilde_navn = "Abuse.ch Feodo tracker"

        try:
            foresporsel = urllib.request.Request(
                self.feodo_url,
                headers = {"User-Agent": "CSOC-CTI-Integrator/1.0"}
            )
            with urllib.request.urlopen(foresporsel, timeout = 5.0) as respons:
                status_kode = respons.getcode()
                ra_data = respons.read().decode("utf-8")
                responstid_ms = (time.perf_counter() - start_tid) * 1000

                json_data = json.loads(ra_data)
                ioc_liste = []

                # Henter og normaliserer dataen fra json
                # henter IP
                for element in json_data:
                    ip = element.get("ip_address")
                    if not ip:
                        continue

                    # Henter dato eller setter dato til i dag hvis dato ikke er funnet
                    sist_sett_ra = element.get("last_online") or element.get("first_seen", "")
                    sist_sett_dato = (
                        sist_sett_ra.split(" ")[0]
                        if sist_sett_ra
                        else datetime.now().strftime("%Y-%m-%d")
                    )

                    # legger inn data i ioc dict med fallbacks for worst case uten info
                    ioc_liste.append({
                        "ip": ip,
                        "port": int(element.get("port", 443)),
                        "type_skadevare": element.get("malware", "ukjent"),
                        "status": element.get("status", "online"),
                        "sist_sett": sist_sett_dato,
                        "kilde_feed": "FeodoTracker",
                    })

                # Legger inn api helse data i db
                api_helse_data = {
                    "kilde_navn": kilde_navn,
                    "status_kode": status_kode,
                    "responstid_ms": responstid_ms,
                    "antall_hentet": len(ioc_liste),
                    "melding": "OK - Info hentet og synkronisert",
                }

                lagret_antall = self.db.insert_ioc_liste(ioc_liste)
                self.db.insert_api_helse(api_helse_data)

                return lagret_antall

        # I tilfelle tilkoblingsfeil
        except Exception:
            responstid_ms = (time.perf_counter() - start_tid) * 1000
            antall_hentet = 0

            api_helse_data = {
                "kilde_navn": kilde_navn,
                "status_kode": 503,
                "responstid_ms": responstid_ms,
                "antall_hentet": antall_hentet,
                "melding": "Tilkoblingsfeil - Kunne ikke nå API",
            }
            self.db.insert_api_helse(api_helse_data)
            return 0

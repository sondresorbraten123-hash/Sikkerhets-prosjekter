import ipaddress
import json
import sqlite3
import urllib.request

# Klasse for henting av info til potensielt truende IP addresser
class TrusselInfo:

    # Konstruktør med databse tilkobling
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    # funksjon som tar imot ip addresse og returnerer info ISP, org og lokasjon
    def ip_info(self, ip: str) -> str:

        # Sjekker om IP addressen er intern eller privat
        # foreks 192.168.1.50 eller 10.0.10.15
        # Sjekker også om det faktisk er sendt med en IP
        try:
            ip_objekt = ipaddress.ip_address(ip)
            if ip_objekt.is_private or ip_objekt.is_reserved:
                return "Privat/Reservert IP"
        except ValueError:
            return "Mangler eller ugydig IP"
        

        # Sjekker om vi har sjekket IP addressen fra før ved å se i db
        markor = self.conn.cursor()
        markor.execute("SELECT land, isp, org FROM tidligere_sjekket_ip_addresse WHERE ip = ?", (ip,),)
        sjekket_tidligere = markor.fetchone()
        if sjekket_tidligere:
            markor.close()
            return f"Land: {sjekket_tidligere['land']} | ISP: {sjekket_tidligere['isp']} ORG: {sjekket_tidligere['org']}"
        
        # Sjekker IP addressen mot ip-api sitt gratis endepunkt for ip sjekker
        ip_api_url = f"http://ip-api.com/json/{ip}?fields=status,country,isp,org"
        try:
            # HTTPS forespørsel med egen user agent
            foresporsel = urllib.request.Request(
                ip_api_url, headers = {"User-Agent": "CSOC-Telemetry-Pipeline/1.0"}
            )
            with urllib.request.urlopen(foresporsel, timeout = 3.0) as response:
                # Leser data fra svares og tar det fra json til python dictionary
                data = json.loads(response.read().decode("utf-8"))
                if data.get("status") == "success":
                    land = data.get("country", "ukjent")
                    isp = data.get("isp", "ukjent")
                    org = data.get("org", "ukjent")

                    markor.execute("""
                        INSERT INTO tidligere_sjekket_ip_addresse(ip, land, isp, org)
                        VALUES(?, ?, ?, ?)
                    """, (ip, land, isp, org))
                    self.conn.commit()

                    return f"Land: {land} | ISP: {land} | Org: {org}"

        except Exception:
            return f"Kan ikke hente info ({type(Exception).__name__})"

        return "Kan ikke hente info (Ukjent feil)"
        

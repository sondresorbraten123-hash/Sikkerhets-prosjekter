import math
from src.database import TelemetriDatabase
from src.trusselInfo import TrusselInfo

# Klasse for algoritmer og deteksjon til å se etter angrep i CSOC logg
class CSOCAnalyse:

    # Konstruktør for klassen som setter opp info_henter og database tilkobling
    def __init__(self, db:TelemetriDatabase, info_henter: TrusselInfo):
        self.db = db
        self.info_henter = info_henter

    # Funksjon for å oppdage suksessfulle brute force angrep med fiksede minimum forsøk og tidsramme
    def brute_force_analyse(self, min_feilede_forsok: int = 5, tidsramme_minutter: int = 15) -> int:

        markor = self.db.conn.cursor()
        
        # Jeg bruker WHERE, AND og subqueries her fordi jeg synes dette blir enklere enn JOIN 
        # Jeg bruker også en egen variabel for spørringen siden det blir en såpass stor spørring
        # Spørringen tar IPen og regner ut hvor lang tid det tok før suksess og 
        # hvor mange tidligere feil
        # Så sjekker den om tiden og feilene er innenfor rammen jeg satte opp tidligere
        sporring = """
            SELECT fra_ip, brukernavn, susksess_tid, feil
            FROM (
                SELECT h.fra_ip, h.brukernavn. h.tidsstempel AS suksess_tid,
                (
                    SELECT COUNT(*)
                    FROM hendelse he
                    WHERE he.fra_ip = h.fra_ip
                    AND he.brukernavn = h.brukernavn
                    AND he.hendelses_type = 'AUTH_FAILED'
                    AND he.tidsstempel <= h.tidsstempel
                    AND (strftime('%s', h.tidsstempel) - strftime('%s', he.tidsstempel)) <= (? * 60)
                ) AS feil
                FROM hendelse h
                WHERE h.hendelses_type = 'AUTH_SUCCESS'
            )
            WHERE feil >= ?
        """

        markor.execute(sporring, (min_feilede_forsok, tidsramme_minutter))
        sql_bf_data = markor.fetchall()

        # Ser om det er noen nye alarmer og henter info til IP og legger inn i db
        nye_alarmer = 0
        for r in sql_bf_data:
            ip = r["fra_ip"]
            bruker = r["brukernavn"]
            antall_feilede_forsok = r["feil"]
            suksess_tidsstempel = r["suskess_tid"]

            # Henter info til IPen før den lagres i db
            kontekst = self.info_henter.ip_info(ip)
            beskrivelse = (
                f"Bruker '{bruker}' logget inn {suksess_tidsstempel} etter "
                f"{antall_feilede_forsok} feilede forsøk innen {tidsramme_minutter} minutter"
            )

            # Lagrer alarmen i db
            


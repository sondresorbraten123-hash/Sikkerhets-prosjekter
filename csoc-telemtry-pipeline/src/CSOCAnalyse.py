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
            SELECT fra_ip, brukernavn, suksess_tid, feil
            FROM (
                SELECT h.fra_ip, h.brukernavn, h.tidsstempel AS suksess_tid,
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

        markor.execute(sporring, (tidsramme_minutter, min_feilede_forsok))
        sql_bf_data = markor.fetchall()

        # Ser om det er noen nye alarmer og henter info til IP og legger inn i db
        nye_alarmer = 0
        for r in sql_bf_data:
            ip = r["fra_ip"]
            bruker = r["brukernavn"]
            antall_feilede_forsok = r["feil"]
            suksess_tidsstempel = r["suksess_tid"]

            # Henter info til IPen før den lagres i db
            kontekst_insert = self.info_henter.ip_info(ip)
            beskrivelse_insert = (
                f"Bruker '{bruker}' logget inn {suksess_tidsstempel} etter "
                f"{antall_feilede_forsok} feilede forsøk innen {tidsramme_minutter} minutter"
            )

            # Lagrer alarmen i db
            if self.db.insert_alarm(
                regel_navn = "Brute Force etterfulgt av suksessfull innlogging",
                alvorlighetsgrad = "KRITISK",
                fra_ip = ip,
                angrepet_bruker = bruker,
                beskrivelse = beskrivelse_insert,
                kontekst = kontekst_insert
            ):
                nye_alarmer += 1
        
        markor.close()
        return nye_alarmer

    # Z-score analyse for å oppdage statistiske anomalier ved hjelp av z-score/standardavvik
    # Fanger opp foreks passord spray
    def z_score_analyse(self, z_terskel: float = 2.5) -> int:
        # Åpner og kobler til db for å hente data
        markor = self.db.conn.cursor()
        markor.execute("""
            SELECT strftime('%Y-%m-%d %H:00', tidsstempel) AS time_teller, COUNT(*) AS antall_hendelser
            FROM hendelse
            GROUP BY time_teller
            ORDER BY time_teller ASC
        """)
        # Henter hendelser gruppert på timer
        timer = markor.fetchall()

        # Det trengs minst 4 timer med data for at analysen skal gi mening
        # Eller så blir det ikke nok data for at analysen skal fange opp avvik
        if len(timer) < 4:
            return 0

        # Lager en listevariabel med antall hendelser for hver time
        hendelser_per_time = [hendelse["antall_hendelser"] for hendelse in timer]

        # Regner ut gjennomsnittet av hendelser i timen
        gjennomsnitt = sum(hendelser_per_time) / len(hendelser_per_time)

        # Regner ut variansen av hendelser per time, altså forskjellen i hendelser hver time
        varians = sum((x - gjennomsnitt) ** 2 for x in hendelser_per_time) / len(hendelser_per_time)

        # regner ut standardavviket, for å se hvor mye antall hendelser svinger opp og ned hver time
        standardavvik = math.sqrt(varians)

        # Hvis alle timer har nøyaktig det samme antallet hendelser
        if standardavvik == 0:
            return 0

        # Regenr ut selve z-scoren for hver time, formelen for z-score er: Z = (observasjon - gjennomsnitt) / standardavvik
        # Hvis z-score er mer enn 2.5 betyr det at standardavviket denne timen er 2.5 over normalen
        # Dette har mindre enn 1% sannsynlighet for å skje helt tilfeldig
        nye_alarmer = 0
        for rad in timer:
            observasjoner = rad["antall_hendelser"]
            time_nr = rad["time_teller"]
            z_score = (observasjoner - gjennomsnitt) / standardavvik

            # Hvis z_score er over 2.5 (terskel satt i funksjon deklarasjonen)
            # Sjekker vi hvilken IP som var ansvarlig for mesteparten av loggene denne timen via db
            if z_score >= z_terskel:
                markor.execute("""
                    SELECT fra_ip, COUNT(*) AS ip_teller
                    FROM hendelse
                    WHERE strftime('%Y-%m-%d %H:00', tidsstempel) = ?
                    GROUP BY fra_ip
                    ORDER BY ip_teller DESC
                    LIMIT 1
                """, (time_nr,))
                ansvarlig_ip_rad = markor.fetchone()
                ansvarlig_ip = ansvarlig_ip_rad["fra_ip"] if ansvarlig_ip_rad else "Ukjent"
                ansvarlig_ip_antall = ansvarlig_ip_rad["ip_teller"] if ansvarlig_ip_rad else 0

                # henter mer info på den IPen som er ansvarlig for mest logger denne avvikstimen
                # og lager en beskrivelse av avviket
                ansvarlig_ip_info = self.info_henter.ip_info(ansvarlig_ip)
                beskrivelse_insert = (
                    f"Avvikende log antall i timen [{time_nr}]: {observasjoner} hendelser "
                    f"(Basislinje: gjennomsnitt = {gjennomsnitt:.1f}, standardavvik = {standardavvik:.1f}, z_score = {z_score:.2f}) "
                    f"IP ansvarlig for mesteparten: {ansvarlig_ip} med ({ansvarlig_ip_antall}) hendelser"
                )
                
                # Legger alarmen inn i db
                if self.db.insert_alarm(
                    regel_navn = "Statistisk avvik av antall logger på en time (z-score)",
                    alvorlighetsgrad = "HØY",
                    fra_ip = ansvarlig_ip,
                    angrepet_bruker = "FLERE",
                    beskrivelse = beskrivelse_insert,
                    kontekst = ansvarlig_ip_info
                ):
                    nye_alarmer += 1
        markor.close()
        return nye_alarmer
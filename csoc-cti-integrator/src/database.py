import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Set

# Lager klassen som skal bruker for databasehåndteringen
class CTIDatabase:

    # Konstruktøren for database klassen som passer på at stien er riktig og opretter den
    # hvis den ikke er laget ennå
    def __init__(self, db_sti: str = "data/csoc_cti.db"):
        Path(db_sti).parent.mkdir(parents = True, exist_ok = True)
        self.db_sti = db_sti
        self.conn = sqlite3.connect(self.db_sti)

        # Gjør at radene fra databsen kan leses enkelt som en python dictionary
        self.conn.row_factory = sqlite3.Row

        # Kjører funksjonen for å oprette alle tabeller og indekser
        self.oprett_tabeller_og_indekser()

    # Funksjonen for å oprette alle tabeller og indekser
    def oprett_tabeller_og_indekser(self) -> None:
        # Kobler til en markør til db
        markor = self.conn.cursor()

        # Første tabellen er for IOC (Indicators of compromise)
        # For å se etter data som sier noe om at systemet er i fare
        # Dataen skal bli hentet fra trussel feeds som sporer forskjellige type malware
        markor.execute("""
            CREATE TABLE IF NOT EXISTS ioc (
                ip TEXT PRIMARY KEY NOT NULL,
                port INTEGER,
                type_skadevare TEXT NOT NULL,
                status TEXT NOT NULL,
                sist_sett TEXT NOT NULL,
                kilde_feed TEXT NOT NULL,
                tid_oppdatert_lokalt DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Andre tabellen er for å overvåke helsen til API integrasjonen
        # for å sikre enklere feilsøking om en API skulle være nede
        markor.execute("""
            CREATE TABLE IF NOT EXISTS api_helse (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tidsstempel DATETIME DEFAULT CURRENT_TIMESTAMP,
                kilde_navn TEXT NOT NULL,
                status_kode INTEGER NOT NULL,
                responstid_ms FLOAT NOT NULL,
                antall_hentet INTEGER NOT NULL,
                melding TEXT NOT NULL
            )
        """)

        # Tredje tabellen er for hvitelisting så det ikke kommer opp masse falske positiver hele tiden
        markor.execute("""
            CREATE TABLE IF NOT EXISTS hviteliste(
            ip TEXT PRIMARY KEY,
            beskrivelse TEXT NOT NULL,
            lagt_til DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Fjerde tabellen er for ferdig korrelerte C2 alarmer (command and control traffikk)
        markor.execute("""
            CREATE TABLE IF NOT EXISTS c2_alarm(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                oprettet DATETIME DEFAULT CURRENT_TIMESTAMP,
                tidsstempel TEXT NOT NULL,
                intern_ip TEXT NOT NULL,
                ekstern_ip TEXT NOT NULL,
                ekstern_port INTEGER NOT NULL,
                type_skadevare TEXT NOT NULL,
                bytes_sendt INTEGER NOT NULL,
                risiko_score INTEGER NOT NULL,
                alvorlighetsgrad TEXT NOT NULL,
                beskrivelse TEXT NOT NULL,
                UNIQUE(tidsstempel, intern_ip, ekstern_ip, ekstern_port)
            )
        """)

        # Opretting av noen indekser for raskere oppslag av type_skadevare og risiko_score
        # For å raskt se de mest kritiske alarmene
        markor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ioc_type ON ioc(type_skadevare)
        """)

        markor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alarm_score ON c2_alarm(risiko_score DESC)
        """)

        # Legger inn noen velkjente IPer til hvitelisten som standard
        standard_hviteliste = [
            ("1.1.1.1", "Cloudflare DNS - Godkjent resolver"),
            ("8.8.8.8", "Google DNS - Godkjent resolver"),
            ("10.0.50.10", "Intern betalings gateway - Kritisk infrastruktur"),
        ]

        # Setter inn alle på en gang med executemany og hvisde allerede er i db
        # blir de ignorert pga IGNORE
        markor.executemany("""
            INSERT OR IGNORE INTO hviteliste(ip, beskrivelse) VALUES (?, ?)
        """, standard_hviteliste)

        # konfirmerer data og lukker db markør
        self.conn.commit()
        markor.close()


    # Funksjon for å oppdatere db med IOC informasjon fra trussel feeder
    def insert_ioc_liste(self, ioc_info_liste: List[Dict[str, Any]]) -> int:
        markor = self.conn.cursor()
        antall_for = self.conn.total_changes

        # Setter inn dataen med en oppdatering om det er lik IP addresse
        markor.executemany("""
            INSERT INTO ioc(
                ip, port, type_skadevare, status, sist_sett, kilde_feed
                ) VALUES(:ip, :port, :type_skadevare, :status, :sist_sett, :kilde_feed)
            ON CONFLICT(ip) DO UPDATE SET
                status = excluded.status,
                sist_sett = excluded.sist_sett,
                tid_oppdatert_lokalt = CURRENT_TIMESTAMP
        """, ioc_info_liste)

        self.conn.commit()
        markor.close()
        # Returnerer hvor mange endringer som ble gjort
        return self.conn.total_changes - antall_for

    # Legger inn helsestatusen for api integrasjoner
    def insert_api_helse(self, api_helse_data: Dict[str, Any]) -> None:
        markor = self.conn.cursor()
        markor.execute("""
            INSERT INTO api_helse(
                kilde_navn, status_kode, responstid_ms, antall_hentet, melding
            ) VALUES(:kilde_navn, :status_kode, :responstid_ms, :antall_hentet, :melding)
        """, api_helse_data)
        self.conn.commit()
        markor.close()

    # Henter alle IOC i en dictionary for enkel bruk
    # bruker IP addresse som nøkkel for lettest mulig oppslag
    def get_ioc_dict(self) -> Dict[str, Dict[str, Any]]:
        markor = self.conn.cursor()
        markor.execute("SELECT * FROM ioc")
        markor_resultat = {rad["ip"]: dict(rad) for rad in markor.fetchall()}
        markor.close()
        return markor_resultat

    # Henter hvitelisten som et SET pga det skal bare sjekkes om en IP er der eller ikke
    def get_hviteliste(self) -> Set[str]:
        markor = self.conn.cursor()
        markor.execute("SELECT ip FROM hviteliste")
        markor_resultat = {rad["ip"] for rad in markor.fetchall()}
        markor.close()
        return markor_resultat

    # Legger inn en c2 alarm, hvis hendelsen ikke er varslet fra før
    def insert_c2(self, c2_data: Dict[str, Any]) -> bool:
        markor = self.conn.cursor()
        antall_for = self.conn.total_changes
        markor.execute("""
            INSERT OR IGNORE INTO c2_alarm(
                tidsstempel, intern_ip, ekstern_ip, ekstern_port, type_skadevare, bytes_sendt,
                risiko_score, alvorlighetsgrad, beskrivelse
            ) VALUES(
                :tidsstempel, :intern_ip, :ekstern_ip, :ekstern_port, :type_skadevare, :bytes_sendt,
                :risiko_score, :alvorlighetsgrad, :beskrivelse
            )
        """, c2_data)

        self.conn.commit()
        markor.close()
        return (self.conn.total_changes - antall_for) > 0

    # Henter siste dataen på api helse
    def get_siste_api_helsedata(self) -> Dict[str, Any]:
        markor = self.conn.cursor()
        markor.execute("SELECT * FROM api_helse ORDER BY id DESC LIMIT 1")
        rad = markor.fetchone()
        markor.close()
        return dict(rad) if rad else {}

    # Hent liste med alle c2 alarmer med høyest risiko_score først
    def get_c2(self) -> List[Dict[str, Any]]:
        markor = self.conn.cursor()
        markor.execute("SELECT * FROM c2_alarm ORDER BY risiko_score DESC, id DESC")
        rader = [dict(rad) for rad in markor.fetchall()]
        markor.close()
        return rader

    # Lukk selve database tilkoblingen
    def lukk(self) -> None:
        self.conn.close()
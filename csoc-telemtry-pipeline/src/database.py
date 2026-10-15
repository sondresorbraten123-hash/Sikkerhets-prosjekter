import sqlite3
from pathlib import Path
from typing import Any, Dict, List

# Klasse for å kommunisere med db
class TelemetriDatabase:

    # Konstruktør for klassen
    def __init__(self, db_sti: str = "data/csoc_telemetri.db"):
        # Passer på at database stien finnes og lager/kobler til db filen
        Path(db_sti).parent.mkdir(parents = True, exist_ok = True)
        self.db_sti = db_sti
        self.conn = sqlite3.connect(self.db_sti)

        # Brukes for å kunne hente data på en enkel måte, likt som ved dictionaries
        self.conn.rader = sqlite3.Row

        # Opretter alle tabeller og indekser som trengs for at db fungerer
        self.oprett_essensielle_db_deler()

    # Selve funksjonen for å oprette tabeller og indekser som trengs
    def oprett_essensielle_db_deler(self) -> None:
        # Kobler til en markør til db
        markor = self.conn.cursor()

        # Opretter tabell for hendelser
        markor.execute("""
            CREATE TABLE IF NOT EXISTS hendelse(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hendelses_hash TEXT UNIQUE NOT NULL,
                tidsstempel TEXT NOT NULL,
                servernavn TEXT NOT NULL,
                tjeneste TEXT NOT NULL,
                hendelses_type TEXT NOT NULL,
                auth_metode TEXT,
                brukernavn TEXT NOT NULL,
                fra_ip TEXT NOT NULL,
                hel_log_linje TEXT NOT NULL
            )
        """)

        # Opretter tabell for IP adresser som er sjekket opp fra før
        # for å slippe å bruke API oppslag hvis IPen har blitt sjekket før
        markor.execute("""
            CREATE TABLE IF NOT EXISTS tidligere_sjekket_ip_adresse(
                ip TEXT PRIMARY KEY,
                land TEXT,
                isp TEXT,
                org TEXT,
                sist_oppdatert DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Opretter tabell for alarmer
        # sikrer også at vi ikke opretter duplikate alarmer hvis analysen kjøres flere ganger
        markor.execute("""
            CREATE TABLE IF NOT EXISTS alarm(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                oprettet DATETIME DEFAULT CURRENT_TIMESTAMP,
                regel_navn TEXT NOT NULL,
                alvorlighetsgrad TEXT NOT NULL,
                fra_ip TEXT,
                angrepet_bruker TEXT,
                beskrivelse TEXT NOT NULL,
                kontekst TEXT,
                UNIQUE(regel_navn, fra_ip, angrepet_bruker, beskrivelse)
            )
        """)

        # Opretter indekser for hendelse tid og hendelses ip med type hendelse
        markor.execute("""
        CREATE INDEX IF NOT EXISTS idx_hendelse_tid ON hendelse(tidsstempel)
        """)
        markor.execute("""
        CREATE INDEX IF NOT EXISTS idx_hendelse_ip_type ON hendelse(fra_ip, hendelses_type)
        """)

        # Lagrer
        self.conn.commit()
        markor.close()

    # Tar imot en liste med hendelser som parser.py opretter og setter det inn i db
    # Returnerer hvor mange endringer den har gjort
    def sett_inn_nye_hendelser(self, hendelser: List[Dict[str, str]]) -> int:
        markor = self.conn.cursor()

        antall_for_insert = self.conn.total_changes

        # Setter inn hele lista på en gang ved hjelp av executemany,
        # og ignorerer feil som hvis hendelsen finnes fra før
        markor.executemany("""
            INSERT OR IGNORE INTO hendelse (
                hendelses_hash, tidsstempel, servernavn, tjeneste, hendelses_type, auth_metode, brukernavn, fra_ip, hel_log_linje
            ) VALUES (
                :hendelses_hash, :tidsstempel, :servernavn, :tjeneste, :hendelses_type, :auth_metode, :brukernavn, :fra_ip, :hel_log_linje
            )
        """, hendelser)

        self.conn.commit()
        markor.close()
        return self.conn.total_changes - antall_for_insert
    
    # Sette inn en ny alarm, returnerer bool hvis den ble satt inn eller ikke
    def insert_alarm(self, regel_navn: str, alvorlighetsgrad: str, fra_ip: str, angrepet_bruker: str, beskrivelse: str, kontekst: str,) -> bool:
        markor = self.conn.cursor()

        antall_for_insert = self.conn.total_changes

        # setter inn parameterene i alarm
        markor.execute("""
            INSERT OR IGNORE alarm(
                regel_navn, alvorlighetsgrad, fra_ip, angrepet_bruker, beskrivelse, kontekst
            ) VALUES(?, ?, ?, ?, ?, ?)
        """, (regel_navn, alvorlighetsgrad, fra_ip, angrepet_bruker, beskrivelse, kontekst))

        self.conn.commit()
        markor.close()

        # returnerer om den gjorde en endring eller ikke
        return (self.conn.total_changes - antall_for_insert) > 0

    # Henter alle alarmer med de nyeste øverst
    def get_alarmer(self) -> List[Dict[str, Any]]:
        markor = self.conn.cursor()
        markor.execute("SELECT * FROM alarm ORDER BY id DESC")

        return [dict(rad) for rad in markor.fetchall()]

    # Lukking av db koblingen
    def lukk(self) -> None:
        self.conn.close()

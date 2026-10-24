import argparse
import logging
from pathlib import Path

from src.database import CTIDatabase
from src.info_henter import TrusselInfoHenter
from src.korrelasjon import KorrelasjonsMotor
from tests.trafikk_gen import generer_brannmur_trafikk

# Setter opp logging
logging.basicConfig(
    level = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S",
)

# Selve kjoringen av programmet
def kjor_cti_pipeline(logg_sti: str, db_sti: str, demo_modus: bool) -> None:
    # Setter opp db stien til db info henter og korrelasjonsmoteren
    db = CTIDatabase(db_sti)
    info_henter = TrusselInfoHenter(db)
    korrelasjon = KorrelasjonsMotor(db)

    # Henter info til db fra Feodo Tracker
    logging.info("Synkroniserer trusselfeed fra Abuse.ch Feodo Tracker...")
    oppdaterte_ioc = info_henter.oppdater_trussel_info()
    helse = db.get_siste_api_helsedata()
    logging.info(
        f"API-status: HTTP {helse.get('status_kode')} ({helse.get('responstid_ms')} ms) ->"
        f" {helse.get('antall_hentet')} aktive C2-IOCer i database"
    )

    # Sjekker om det er en egen loggfil eller om det skal genereres en loggfil
    if demo_modus or not Path(logg_sti).exists():
        logging.info(f"Genererer simulert brannmurtrafikk i '{logg_sti}'...")
        generer_brannmur_trafikk(db, logg_sti)

    # Kjører IOC matching, sjekk mot hviteliste og risikoscoring
    logging.info("Kjører korrelasjonsmotor og risikoscoring på nettverkstrafikk...")
    stats = korrelasjon.analyser_trafikk(logg_sti)

    # skriver ut rapport til terminalen
    alarmer = db.get_c2()
    print("\n CSOC CTI INTEGRATOR - INTEGRASJONSHELSE OG KALIBRERING\n")
    print(f"    Datakilde           : {helse.get('kilde_navn')} [HTTP {helse.get('status_kode')} - {helse.get('responstid_ms')} ms]")
    print(f"    Statusmelding       : {helse.get('melding')}")
    print(f"    Trafikk analysert   : {stats['lest_linjer']} forbindelser ({stats['hviteliste_ignorert']} ekskludert via hviteliste)\n")

    for alarm in alarmer:
        print(f"[{alarm['alvorlighetsgrad']}] Risiko-score: {alarm['risiko_score']}/100 | Trussel: {alarm['type_skadevare']} Botnet C2")
        print(f"    |-- Tidspunkt       : {alarm['tidsstempel']}")
        print(f"    |-- Forbindelse     : {alarm['intern_ip']} -> {alarm['ekstern_ip']}:{alarm['ekstern_port']}")
        print(f"    |-- Analyse         : {alarm['beskrivelse']}\n")

    db.lukk()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description = ("CSOC CTI Info Integrator og IOC korrelasjonsmotor")
    )
    parser.add_argument(
        "--loggfil",
        default = "data/brannmur_trafikk.log",
        help = "Sti til brannmur/nettverkslogg til analyse",
    )
    parser.add_argument(
        "--db",
        default = "data/csoc_cti.db",
        help = "Sti til SQLite database",
    )
    parser.add_argument(
        "--demo",
        action = "store_true",
        help = "Genererer simulert brannmurtrafikk med simulert C2 trafikk før analyse",
    )
    args = parser.parse_args()

    kjor_cti_pipeline(args.loggfil, args.db, args.demo)
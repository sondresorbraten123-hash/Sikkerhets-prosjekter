import argparse
import logging
from pathlib import Path

# importerer egne moduler for å sette alt sammen
from src.CSOCAnalyse import CSOCAnalyse
from src.database import TelemetriDatabase
from src.TrusselInfo import TrusselInfo
from src.parser import parse_log_linje
from tests.log_generator import generer_eksempel_logger


# sette opp utseende av logglinjer i terminalen
logging.basicConfig(
    level = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(message)s",
    datefmt = "%Y-m%-d% %H:%M:%S",
)

# Hovedfunksjon for bruk av prosjektet med kjøring direkte i terminalen med argparse
def kjor_pipeline(log_sti: str, db_sti: str, demo_modus: bool) -> None:
    if demo_modus or not Path(log_sti).exists():
        logging.info("Kjører test-generator for å lage en realistisk log...")
        generer_eksempel_logger(log_sti)

    # Oppretter tilkoblinger og variabler for moduler
    db = TelemetriDatabase(db_sti)
    info_henter = TrusselInfo(db.conn)
    analyse = CSOCAnalyse(db, info_henter)

    # Samler og normaliserer logg med regex i parser filen
    logging.info(f"Leser og normaliserer logger fra '{log_sti}'...")
    parsede_hendelser = []
    log_fil = open(log_sti, "r", encoding = "utf-8")
    for linje in log_fil:
        parsert = parse_log_linje(linje)
        if parsert:
            parsede_hendelser.append(parsert)
    log_fil.close()

    # Lagrer logger i db
    lagret = db.insert_hendelser(parsede_hendelser)
    logging.info(
        f"Prossesert {len(parsede_hendelser)} linjer -> {lagret} nye hendelser lagret i db"
    )

    # Analyserer logger og henter info på potensielt truende IP addresser
    logging.info("Kjører algoritmer for korrelasjon og z-score")
    korrelaterte_alarmer = analyse.brute_force_analyse(min_feilede_forsok = 5, tidsramme_minutter = 15)
    z_score_alarmer = analyse.z_score_analyse(z_terskel = 2.5)
    logging.info(f"Analyse fullført. Nye alarmer: {korrelaterte_alarmer + z_score_alarmer}")

    # Skrive ut oversiktlig rapport av funn i analysen
    alarmer = db.get_alarmer()
    print(f"\nCSOC TELEMETRI PIPELINE - AKTIVE ALARMER ({len(alarmer)})\n")
    for alarm in alarmer:
        print(f"[{alarm['alvorlighetsgrad']}] {alarm['regel_navn']}")
        print(f"    |-- Fra-IP -> Bruker : {alarm['fra_ip']} -> {alarm['angrepet_bruker']}")
        print(f"    |-- Oppdagelse       : {alarm['beskrivelse']}")
        print(f"    |-- Trussel Info     : {alarm['kontekst']}")
    
    # Lukker database tilkobling
    db.lukk()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description = "CSOC Telemetri Mottaker og Avviksnalyse"
    )
    parser.add_argument(
        "--loggfil",
        default = "data/auth_sample.log",
        help = "Sti til loggfilen som skal analyseres",
    )
    parser.add_argument(
        "--db",
        default = "data/csoc_telemtri.db",
        help = "Sti til SQLite database",
    )
    parser.add_argument(
        "--demo",
        action = "store_true",
        help = "Genererer testlogg til testing av programmet",
    )
    args = parser.parse_args()

    kjor_pipeline(args.loggfil, args.db, args.demo)



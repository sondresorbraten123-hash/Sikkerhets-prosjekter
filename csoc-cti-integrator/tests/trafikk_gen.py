from datetime import datetime, timedelta
from pathlib import Path
import random
from src.database import CTIDatabase

# Denne filen er for å generere brannmurtraffikk for testing til systemet via --demo
# Det blir generert traffikk med traffikk fra ekte c2 alarmer som laget tidligere
# Loggene er generert i likhet med NetFlow logger for at programmet skal kunne brukes sammen med ekte logger
# Men det funker fortsatt bare med tcp og allow uten redigering av regex
def generer_brannmur_trafikk(db: CTIDatabase, filsti: str = "data/brannmur_trafikk.log") -> None:
    # Sjekker at sti og filmapper eksisterer og blir laget om de ikke er der
    Path(filsti).parent.mkdir(parents = True, exist_ok = True)

    # starttid for loggene og kjente IP addresser
    start_tid = datetime.now().replace(microsecond = 0) - timedelta(hours = 2)
    interne_klienter = ["10.0.20.14", "10.0.20.25", "10.0.20.88", "10.0.50.10"]
    kjente_eksterne_iper = ["142.250.74.110", "29.190.151.68", "151.101.1.69", "1.1.1.1"]
    linjer = []

    # Genererer vanlig trafikk
    for i in range(150):
        tid = (start_tid + timedelta(seconds = i * 40)).strftime("%Y-%m-%dT%H:%M:%S")
        intern_ip = random.choice(interne_klienter)
        ekstern_ip = random.choice(kjente_eksterne_iper)
        port = 53 if ekstern_ip == "1.1.1.1" else 443
        bytes_sendt = random.randint(400, 18000)

        linjer.append(
            f"{tid} ALLOW TCP {intern_ip} -> {ekstern_ip}:{port} bytes={bytes_sendt}"
        )

    # Henter ut opptil 2 c2 servere fra ioc tabellen i databasen til å simulere ekte angrep
    alle_ioc = list(db.get_ioc_dict().values())

    if len(alle_ioc) >= 1:
        ioc_1 = alle_ioc[0]
        tid_1 = (start_tid + timedelta(minutes = 35)).strftime("%Y-%m-%dT%H:%M:%S")
        linjer.append(f"{tid_1} ALLOW TCP 10.0.20.88 -> {ioc_1['ip']}:{ioc_1['port']} bytes=1850000")
    
    if len(alle_ioc) >= 2:
        ioc_2 = alle_ioc[1]
        tid_2 = (start_tid + timedelta(minutes = 75)).strftime("%Y-%m-%dT%H:%M:%S")
        linjer.append(f"{tid_2} ALLOW TCP 10.0.20.14 -> {ioc_2['ip']}:{ioc_2['port']} bytes=1240")

    # Sorterer loggen så tidene er i riktig rekkefølge og skriver til logfil
    linjer.sort()
    loggfil = open(filsti, "w", encoding = "utf-8")
    for linje in linjer:
        loggfil.write(linje + "\n")
    loggfil.close()
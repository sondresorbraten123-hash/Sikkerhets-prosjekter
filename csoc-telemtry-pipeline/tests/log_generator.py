import random
from datetime import datetime, timedelta
from pathlib import Path


# Lager eksempel logg auth_sample.log for testdata
def generer_eksempel_logger(filepath: str = "data/auth_sample.log") -> None:
    Path(filepath).parent.mkdir(parents = True, exist_ok = True)
    start_tid = datetime.now().replace(minute = 0, second = 0, microsecond = 0) - timedelta(hours = 12)

    normale_brukere = ["sondre", "admin_ops", "svc_backup", "db_maint"]
    interne_IPer = ["10.0.10.15", "10.0.10.22", "10.0.10.40", "192.168.1.50"]
    IPer_for_nettverks_støy = ["45.33.32.156", "103.253.41.2", "91.189.88.152"]

    linjer_til_log = []
    pid = 1000

    # Generere baseline data for z-score algoritmen skal lære "normal" oppførsel i de første 11 timene
    for time_offset in range(11):
        time_na = start_tid + timedelta(hours=time_offset)
        antall_hendelser = random.randint(8, 16)

        for hendelse in range(antall_hendelser):
            # Lager timestamp i (ÅÅÅÅ-MM-DDTHH:MM:SS) format
            hendelse_tid = (
                time_na + timedelta(minutes = random.randint(0, 59), seconds = random.randint(0, 59))
                ).strftime("%Y-%m-%dT%H:%M:%S")
            pid += 1

            # Vellykede forsøk 80% av tiden
            if random.random() < 0.8:
                bruker = random.choice(normale_brukere)
                ip = random.choice(interne_IPer)
                linjer_til_log.append(
                    f"{hendelse_tid} nb-srv-01 sshd[{pid}]: Akseptert publickey for {bruker} "
                    f"fra {ip} port {random.randint(40000, 60000)} ssh2"
                )
            
            # Feilede forsøk 20% av tiden
            else:
                bruker = random.choice(normale_brukere)
                ip = random.choice(IPer_for_nettverks_støy)
                linjer_til_log.append(
                    f"{hendelse_tid} nb-srv-01 sshd[{pid}]: Feilet passord for bruker {bruker} "
                    f"fra {ip} port {random.randint(40000, 60000)} ssh2"
                )

    # Brute force angrep som vellykes til slutt i time 12, designet for å bli fanget opp
    angrep_tid = start_tid + timedelta(hours = 11)
    angrep_ip = "185.220.101.45" #TOR node som bør bli fanget av api
    angrepet_bruker = "svc_payment"

    for forsok in range(7):
        hendelse_tid = (angrep_tid + timedelta(minutes = 10, seconds = forsok * 8)).strftime("%Y-%m-%dT%H:%M:%S")
        pid += 1
        linjer_til_log.append(
            f"{hendelse_tid} nb-srv-01 sshd[{pid}]: Feilet passord for {angrepet_bruker} "
            f"fra {angrep_ip} port {5100 + forsok} ssh2"
        )
    
    # Suksessfult angrep etter 7 feilede forsøk
    hendelse_tid_suksess = (angrep_tid + timedelta(minutes = 11, seconds = 5)).strftime("%Y-%m-%dT%H:%M:%S")
    pid += 1
    linjer_til_log.append(
        f"{hendelse_tid_suksess} nb_srv-01 sshd[{pid}]: Akseptert passord for {angrepet_bruker} "
        f"fra {angrep_ip} port 51009S ssh2"
    )

    # Passord spray angrep som spytter ut 95 feilede innloggingsforsøk, mange hendelser på kort tid skal bli fanget opp
    spray_angrep_ip = "198.51.100.88"
    for forsok in range(95):
        hendelse_tid = (angrep_tid
        + timedelta(minutes = random.randint(15, 55), seconds = random.randint(0, 59))
        ).strftime("%Y-%m-%dT%H:%M:%S")
        pid += 1
        linjer_til_log.append(
            f"{hendelse_tid} nb-srv-01 sshd[{pid}]: Feilet passord for ukjent bruker bruker{forsok} "
            f"fra {spray_angrep_ip} port {random.randint(30000, 60000)} ssh2"
        )

    #Sorterer alle hendelser til riktige tider for loggen som er opprettet
    # pga formateringen til hendelses_tid, kan vi enkelt gjøre det alfabetisk med .sort()
    linjer_til_log.sort()

    # Legger til alle linjene i logfil
    log_fil = open(filepath, "w", encoding = "utf-8")
    for linje in linjer_til_log:
        log_fil.write(linje + "\n")
    log_fil.close()

    print(f"[+] Genererte {len(linjer_til_log)} logglinjer til '{filepath}'.")

if __name__ == "__main__":
    generer_eksempel_logger()
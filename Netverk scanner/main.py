import socket
import concurrent.futures



def scan_port(target, p):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    result = s.connect_ex((target, p))

    if result == 0:
        banner_info = "Banner ikke funnet"

        try:
            if p == 80 or p == 443:
                http_request = b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n"
                s.send(http_request)
            
            banner = s.recv(1024)

            if banner:
                banner_info = banner.decode('utf-8', errors = 'ignore').strip()
                banner_info = banner_info.split('\n')[0]

        except socket.timeout:
            pass

        except Exception:
            banner_info = f"Kan ikke hente banner info, error: {Exception}"

        print(f"[+] Port: {p} er åpen, Banner: {banner_info}")

        apne_porter.append((p, banner_info))

    s.close()



def scan_nettverk(target, startP, sluttP):
    print("Skanner netverk...")
    trader = []

    with concurrent.futures.ThreadPoolExecutor(max_workers = 500) as executor:
        for p in range(startP, sluttP + 1):
            executor.submit(scan_port, target, p)
    
    apen = len(apne_porter)
    lukket = (sluttP - startP + 1) - apen

    print(f"Skanning ferdig \nAntall åpne porter: {apen} \nAntall lukkede porter: {lukket}")

    if apen > 0:
        print("[+] Åpne porter:")
        apne_porter.sort()
        for p, b in apne_porter:
            print(f"[+] Port: {p}, Banner: {b}")
    else:
        print("[-] Ingen åpne porter")




target = input("Skriv inn en IP/nettadresse for testing: ")
print("Skriv inn port du vil starte fra, til og med siste port du vil skanne")
startP = int(input("Skriv inn start port: "))
sluttP = int(input("Skriv inn siste port: "))

apne_porter = []

scan_nettverk(target, startP, sluttP)
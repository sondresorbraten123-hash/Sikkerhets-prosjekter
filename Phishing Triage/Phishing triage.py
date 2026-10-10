import sys
import os
from urllib.parse import urlparse
import requests
import base64


def noytraliser_url(url):
    url = url.replace('https://', 'hxxps://').replace('http://', 'hxxp://')
    return url

def sjekk_url(input_url):
    domene = urlparse(input_url).netloc
    url_id = base64.urlsafe_b64encode(input_url.encode()).decode().strip("=")
    api_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
    
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        print("[-] Feil: Miljøvariabelen 'VT_API_KEY' mangler.")
        print("[-] Kjør: export VT_API_KEY='din_nøkkel_her' i terminalen først.")
        return False
    
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        
        stats = data['data']['attributes']['last_analysis_stats']
        
        antall_malicious = stats['malicious']
        antall_suspicious = stats['suspicious']
        totale_treff = antall_malicious + antall_suspicious
        
        if totale_treff > 0:
            print(f"[-] {totale_treff} sikkerhetsmotorer flagger {noytraliser_url(input_url)} som farlig!")
            return True
        else:
            print(f"[+] Ingen umiddelbare treff for {noytraliser_url(input_url)}.")
            return False
    elif response.status_code == 404:
        print(f"[-] URLen finnes ikke i VirusTotals database (ikke skannet før).")
        return False
    else:
        print(f"[-] Ingen kontakt med API, Kode: {response.status_code}")
        return False


input_url = input("[*] Please enter a URL: ").lower()
sjekk_url(input_url)
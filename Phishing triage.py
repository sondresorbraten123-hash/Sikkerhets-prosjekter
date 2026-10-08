def noytraliser_url(url):
    url = url.replace('https://', 'hxxps://').replace('http://', 'hxxp://')
    return url


input_url = noytraliser_url(input("[*] Please enter a URL: ").lower())
print("[+] URL is : ",input_url)

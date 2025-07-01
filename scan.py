import requests
import os
from dotenv import load_dotenv
from datetime import datetime, timezone
import csv
import socket
from urllib.parse import urlparse

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

headers = {
    "x-apikey": API_KEY
}
print(f"Made By Omar El nmrawy")
# On lit les lignes du fichier iocs.txt (les IPs ou URLs à analyser)
with open("iocs.txt", "r") as f:
    lines = [line.strip() for line in f.readlines()]

results = []

# On boucle sur chaque ligne du fichier
for line in lines:
    line = line.strip()

    # Si c’est une URL, on récupère juste le nom de domaine
    if line.startswith("http://") or line.startswith("https://"):
        parsed = urlparse(line)
        domain = parsed.hostname
    else:
        domain = line

    # Si c’est un domaine, on essaie d’avoir l’IP associée
    # Sinon, c’est une IP donc on essaie de trouver le domaine lié (reverse DNS)
    if not domain.replace('.', '').isdigit():
        try:
            ip = socket.gethostbyname(domain)
            resolved_domain = domain
            print(f"\nRésolu {domain} → {ip}")
        except socket.gaierror:
            print(f"\n❌ Impossible de résoudre : {domain}")
            continue
    else:
        ip = domain
        try:
            resolved_domain = socket.gethostbyaddr(ip)[0]
            print(f"\nRésolu IP {ip} → domaine : {resolved_domain}")
        except socket.herror:
            resolved_domain = "//"
            print(f"\n⚠️ IP {ip} non résolue en domaine")

    # On envoie une requête à l’API VirusTotal avec l’IP
    response = requests.get(BASE_URL + ip, headers=headers)
    if response.status_code == 200:
        data = response.json()
        attributes = data["data"]["attributes"]

        # On récupère les stats de détection (malicious, harmless, etc.)
        malicious = attributes["last_analysis_stats"]["malicious"]
        suspicious = attributes["last_analysis_stats"]["suspicious"]
        harmless = attributes["last_analysis_stats"]["harmless"]
        undetected = attributes["last_analysis_stats"]["undetected"]

        # On prend aussi des infos comme l’ASN, le pays, et la date de dernière modif
        asn = attributes.get("asn", "N/A")
        country = attributes.get("country", "N/A")
        timestamp = attributes.get("last_modification_date")
        last_mod = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if timestamp else "N/A"

        # Si il y a du "malicious", on met un ⚠️
        flag = "⚠️" if malicious > 0 else ""
        print(f"\n[IP] {ip} {flag}")
        print(f"  Domaine : {resolved_domain}")
        print(f"  ASN: {asn} | Country: {country}")
        print(f"  Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Undetected: {undetected}")
        print(f"  Last update: {last_mod}")

         # On stocke les infos dans la liste pour plus tard
        results.append([ip, resolved_domain, asn, country, malicious, suspicious, harmless, undetected, last_mod])
    else:
        print(f"\n[IP] {ip} → ❌ Error {response.status_code}: {response.text}")

# À la fin, on exporte tous les résultats dans un fichier CSV
with open("results.csv", mode="w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Made By Omar El nmrawy"])
    writer.writerow(["IP", "Domaine", "ASN", "Country", "Malicious", "Suspicious", "Harmless", "Undetected", "Last Update"])
    writer.writerows(results)

print("\n✅ Résultats exportés dans 'results.csv'")

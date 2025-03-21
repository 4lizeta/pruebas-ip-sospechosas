import requests
import json
import os
from github import Github

# Configuración
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # Token de GitHub (se obtiene en el workflow)
REPO_NAME = "josesanchezaligo/pruebas-ip-sospechosas"  # Cambia esto por tu usuario y nombre de repositorio
IP_FILE = "lista.txt"
OUTPUT_FILE = "filtered_ips.txt"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Obtener contenido del archivo de IPs desde GitHub
def get_ips_from_github():
    g = Github(GITHUB_TOKEN)
    repo = g.get_repo(REPO_NAME)
    file_content = repo.get_contents(IP_FILE)
    return file_content.decoded_content.decode("utf-8").splitlines()

# Consultar la API de AbuseIPDB
def check_ip(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "verbose": ""
    }
    response = requests.get(url, headers=headers, params=params)
    data = response.json()
    return data["data"]["abuseConfidenceScore"]

# Filtrar IPs
def filter_ips(ips):
    filtered_ips = []
    for ip in ips:
        score = check_ip(ip)
        print(f"IP: {ip} - Score: {score}")
        if score > 75:
            filtered_ips.append(ip)
    return filtered_ips

# Guardar IPs filtradas y subir cambios a GitHub
def update_github_file(filtered_ips):
    g = Github(GITHUB_TOKEN)
    repo = g.get_repo(REPO_NAME)
    file_content = repo.get_contents(OUTPUT_FILE)
    
    new_content = "\n".join(filtered_ips)
    
    if file_content.decoded_content.decode("utf-8") != new_content:
        repo.update_file(OUTPUT_FILE, "Actualización de IPs filtradas", new_content, file_content.sha)
        print("Archivo actualizado en GitHub.")
    else:
        print("No hay cambios en las IPs.")

if __name__ == "__main__":
    ips = get_ips_from_github()
    filtered_ips = filter_ips(ips)
    update_github_file(filtered_ips)

import requests
import json
import os
import time
from github import Github

# Configuración
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # Token de GitHub (se obtiene en el workflow)
REPO_NAME = "josesanchezaligo/pruebas-ip-sospechosas"  # Cambia esto por tu usuario y nombre de repositorio
IP_FILE = "lista.txt"
OUTPUT_FILE = "filtered_ips.txt"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Claves API de AbuseIPDB (en orden de prioridad)
ABUSEIPDB_API_KEYS = [
    os.getenv("ABUSEIPDB_API_KEY_1"),
    os.getenv("ABUSEIPDB_API_KEY_2"),
    os.getenv("ABUSEIPDB_API_KEY_3")
]

# Índice de la API Key actual
current_api_key_index = 0

# Obtener contenido del archivo de IPs desde GitHub
def get_ips_from_github():
    g = Github(GITHUB_TOKEN)
    repo = g.get_repo(REPO_NAME)
    file_content = repo.get_contents(IP_FILE)
    return file_content.decoded_content.decode("utf-8").splitlines()

# Función para obtener la API Key actual
def get_current_api_key():
    global current_api_key_index
    if current_api_key_index < len(ABUSEIPDB_API_KEYS):
        return ABUSEIPDB_API_KEYS[current_api_key_index]
    else:
        print("❌ Todas las API Keys han alcanzado su límite de consultas.")
        return None

# Consultar la API de AbuseIPDB con cambio automático de API Key si hay errores
def check_ip(ip):
    global current_api_key_index

    while current_api_key_index < len(ABUSEIPDB_API_KEYS):
        api_key = get_current_api_key()
        if not api_key:
            return None  # No hay API Key disponible

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "verbose": ""
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json()
            return data["data"]["abuseConfidenceScore"]
        elif response.status_code == 429:  # Too Many Requests
            print(f"⚠️ Límite de consultas alcanzado para API Key {current_api_key_index + 1}. Cambiando a la siguiente...")
            current_api_key_index += 1  # Cambia a la siguiente API Key
            time.sleep(2)  # Espera 2 segundos antes de intentar nuevamente
        else:
            print(f"❌ Error al consultar {ip}: {response.status_code} - {response.text}")
            return None

    return None  # Si todas las API Keys fallaron, devuelve None

# Filtrar IPs con score mayor a 75
def filter_ips(ips):
    filtered_ips = []
    for ip in ips:
        score = check_ip(ip)
        if score is not None:
            print(f"🔍 IP: {ip} - Score: {score}")
            if score > 75:
                filtered_ips.append(ip)
        else:
            print(f"⚠️ No se pudo verificar la IP: {ip}")
    return filtered_ips

# Guardar IPs filtradas y actualizar GitHub
def update_github_file(filtered_ips):
    g = Github(GITHUB_TOKEN)
    repo = g.get_repo(REPO_NAME)

    try:
        file_content = repo.get_contents(OUTPUT_FILE)
        existing_ips = file_content.decoded_content.decode("utf-8").splitlines()
    except:
        existing_ips = []

    new_content = "\n".join(filtered_ips)

    if existing_ips != filtered_ips:
        if existing_ips:
            repo.update_file(OUTPUT_FILE, "Actualización de IPs filtradas", new_content, file_content.sha)
        else:
            repo.create_file(OUTPUT_FILE, "Creación de archivo con IPs filtradas", new_content)
        print("✅ Archivo actualizado en GitHub.")
    else:
        print("✅ No hay cambios en las IPs.")

if __name__ == "__main__":
    ips = get_ips_from_github()
    filtered_ips = filter_ips(ips)
    update_github_file(filtered_ips)

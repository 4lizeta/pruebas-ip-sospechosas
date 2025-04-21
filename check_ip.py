import requests
import json
import os
import time
from github import Github

# Configuración
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # Token de GitHub
REPO_NAME = "josesanchezaligo/pruebas-ip-sospechosas"  # Repositorio
IP_FILE = "lista.txt"
OUTPUT_FILE = "ip_sospechosas.txt"

# Claves API de AbuseIPDB
ABUSEIPDB_API_KEYS = list(filter(None, [
    os.getenv("ABUSEIPDB_API_KEY_1"),
    os.getenv("ABUSEIPDB_API_KEY_2"),
    os.getenv("ABUSEIPDB_API_KEY_3"),
    os.getenv("ABUSEIPDB_API_KEY_4")
]))

current_api_key_index = 0  # Índice de API Key actual

def get_ips_from_github():
    """Descargar lista de IPs desde GitHub"""
    url = f"https://raw.githubusercontent.com/{REPO_NAME}/main/{IP_FILE}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text.strip().split("\n")
    else:
        print(f"❌ Error al descargar {IP_FILE}: {response.status_code}")
        return []

def get_current_api_key():
    """Obtener la API Key actual"""
    global current_api_key_index
    return ABUSEIPDB_API_KEYS[current_api_key_index] if current_api_key_index < len(ABUSEIPDB_API_KEYS) else None

def check_ip(ip):
    """Consultar la API de AbuseIPDB con cambio automático de API Key"""
    global current_api_key_index

    while current_api_key_index < len(ABUSEIPDB_API_KEYS):
        api_key = get_current_api_key()
        if not api_key:
            return None

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "verbose": ""}

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            return response.json().get("data", {}).get("abuseConfidenceScore", 0)
        elif response.status_code == 429:  # Límite de consultas
            print(f"⚠️ Límite alcanzado en API Key {current_api_key_index + 1}. Cambiando...")
            current_api_key_index += 1
            time.sleep(2)
        else:
            print(f"❌ Error con {ip}: {response.status_code}")
            return None

    return None  # Si todas las API Keys fallan

def filter_ips(ips):
    """Filtrar IPs con un score mayor a 75"""
    filtered_ips = [ip for ip in ips if (score := check_ip(ip)) is not None and score > 60]
    return filtered_ips

def update_github_file(filtered_ips):
    """Actualizar el archivo en GitHub"""
    g = Github(GITHUB_TOKEN)
    repo = g.get_repo(REPO_NAME)
    # Crear contenido a escribir
    new_content = "\n".join(filtered_ips)
    # Verificar si el archivo existe
    try:
        file_content = repo.get_contents(OUTPUT_FILE)
        existing_ips = file_content.decoded_content.decode("utf-8").split("\n")
        sha = file_content.sha
    except:
        print(f"⚠️ {OUTPUT_FILE} no existe. Será creado.")
        existing_ips, sha = [], None

    # Si el contenido no ha cambiado, no actualizar
    if existing_ips == filtered_ips:
        print("✅ No hay cambios en las IPs.")
        return

    # Si el archivo ya existe, actualizarlo
    if sha:
        repo.update_file(OUTPUT_FILE, "Actualización de IPs filtradas", new_content, sha)
    else:
        repo.create_file(OUTPUT_FILE, "Creación de archivo con IPs filtradas", new_content)
    print("✅ Archivo actualizado en GitHub.")

if __name__ == "__main__":
    ips = get_ips_from_github()
    if ips:
        filtered_ips = filter_ips(ips)
        if filtered_ips:
            update_github_file(filtered_ips)
        else:
            print("⚠️ No se encontraron IPs sospechosas para actualizar.")

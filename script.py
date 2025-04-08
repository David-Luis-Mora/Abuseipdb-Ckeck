import os
import requests
import csv
import argparse
import configparser
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

# Definir la URL base de la API de AbuseIPDB
BASE_URL = "https://api.abuseipdb.com/api/v2/check"
API_KEY = ''  # Sustituye esto por tu propia API key

# Inicializamos el objeto Console para mostrar mensajes
console = Console()

# Función para obtener los reportes de la API
def get_ip_report(ip):
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }
    
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90',  # Puede ajustar este parámetro si quieres buscar más o menos días
    }
    
    response = requests.get(BASE_URL, headers=headers, params=params)
    
    if response.status_code == 200:
        return response.json()
    else:
        console.print(f"[red]Error al obtener los datos para {ip}[/red]")
        return None

# Función para leer los dominios desde un archivo de texto
def read_excluded_domains(file_path):
    try:
        with open(file_path, 'r') as file:
            domains = [line.strip() for line in file.readlines() if line.strip()]
        return domains
    except FileNotFoundError:
        console.print(f"[red]El archivo de dominios excluidos no se encontró: {file_path}[/red]")
        return []

# Función para procesar las IPs desde un archivo de texto
def process_ips(input_file, output_file, excluded_domains):
    with open(input_file, 'r') as f:
        ips = [line.strip() for line in f.readlines()]

    # Crear un archivo CSV para guardar los resultados
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['IP']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        with Progress() as progress:
            task = progress.add_task("[cyan]Procesando IPs...", total=len(ips))
            for ip in ips:
                report = get_ip_report(ip)
                progress.update(task, advance=1)
                
                if report:
                    data = report.get('data', {})
                    domain = data.get('domain', '')  # Tomamos 'domain' o una cadena vacía
                    
                    if domain:  # Verificamos si 'domain' no es None ni vacío
                        # Comprobamos si el dominio está en la lista de dominios excluidos
                        if not any(excluded_domain in domain for excluded_domain in excluded_domains):
                            writer.writerow({
                                'IP': ip
                            })
                    else:
                        # Si no hay dominio, escribimos la IP directamente
                        writer.writerow({
                            'IP': ip
                        })
                else:
                    # Si no hay reporte, escribimos la IP directamente
                    writer.writerow({
                        'IP': ip,
                    })

# Función principal
def main():
    parser = argparse.ArgumentParser(description="Procesar IPs con la API de AbuseIPDB.")
    parser.add_argument('input_file', help="Archivo de texto con las IPs a verificar.")
    parser.add_argument('output_file', help="Archivo CSV donde se guardarán los resultados.")
    parser.add_argument('excluded_domains_file', help="Archivo de texto con los dominios a excluir.")
    args = parser.parse_args()

    # Leer los dominios excluidos desde el archivo proporcionado
    excluded_domains = read_excluded_domains(args.excluded_domains_file)

    # Procesar las IPs
    process_ips(args.input_file, args.output_file, excluded_domains)

if __name__ == "__main__":
    main()

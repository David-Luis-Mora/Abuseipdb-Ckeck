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
API_KEY = 'f01bb1e09d306f0c3493c95fa182d56abd025cb71391827edafd818edc810db879951c8761c2879a'  # Sustituye esto por tu propia API key

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

# Función para procesar las IPs desde un archivo de texto
def process_ips(input_file, output_file):
    # Si quieres excluir dominios específicos de las IPs
    DOMAIN= ['']
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
                # console.print(f"[blue]Procesando IP: {ip}[/blue]")
                report = get_ip_report(ip)
                progress.update(task, advance=1)
                
                if report:
                    data = report.get('data', {})
                    print(data)
                    if not any(excluded in data.get('domain', '').lower() for excluded in DOMAIN):
                        writer.writerow({
                            'IP': ip
                            # 'Reported': data.get('isPublic', 'N/A'),
                            # 'Country': data.get('countryCode', 'N/A'),
                            # 'Usage Type': data.get('usageType', 'N/A'),
                            # 'Abuse Confidence Score': data.get('abuseConfidenceScore', 'N/A')
                        })

                        # console.print(f"[green]IP {ip} procesada con éxito.[/green]")
                else:
                    writer.writerow({
                        'IP': ip,
                        # 'Reported': 'N/A',
                        # 'Country': 'N/A',
                        # 'Usage Type': 'N/A',
                        # 'Abuse Confidence Score': 'N/A'
                    })

        # console.print(f"[bold green]Proceso completado! Los resultados se guardaron en {output_file}[/bold green]")

# Función principal
def main():
    parser = argparse.ArgumentParser(description="Procesar IPs con la API de AbuseIPDB.")
    parser.add_argument('input_file', help="Archivo de texto con las IPs a verificar.")
    parser.add_argument('output_file', help="Archivo CSV donde se guardarán los resultados.")
    args = parser.parse_args()

    # Procesar las IPs
    process_ips(args.input_file, args.output_file)

if __name__ == "__main__":
    main()

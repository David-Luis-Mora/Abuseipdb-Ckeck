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

# Función para procesar las IPs desde un archivo de texto
def process_ips(input_file, output_file):
    # Si quieres excluir dominios específicos de las IPs
    DOMAIN = ['google.com','amazon.com']  # Puedes agregar dominios aquí que desees excluir
    
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
                    print(data)
                    domain = data.get('domain', '')  # Tomamos 'domain' o una cadena vacía
                    
                    if domain:  # Verificamos si 'domain' no es None ni vacío
                        # Comprobamos si el dominio está en la lista de dominios excluidos
                        count = 0
                        for j in DOMAIN:
                            if j in domain:
                                count += 1
                        if count == 0:  # Si no se encuentra ningún dominio excluido
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
    args = parser.parse_args()

    # Procesar las IPs
    process_ips(args.input_file, args.output_file)

if __name__ == "__main__":
    main()

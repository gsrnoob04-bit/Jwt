import json
import requests
import os
import random
import string
import re
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

console = Console()
API_URL = "https://star-jwt-api1.lovable.app/api/public/token?uid={}&password={}"

def generate_random_filename(path):
    random_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return os.path.join(path, f"{random_name}.json")

def extract_uid_password(content):
    pattern = re.compile(r'"uid"\s*:\s*"(\d+)"\s*,\s*"password"\s*:\s*"([A-Fa-f0-9]+)"')
    return pattern.findall(content)

def print_header():
    header_text = Text("🔥 UID Token Fetcher 🔥", style="bold magenta")
    console.print(Panel(header_text, style="cyan", expand=True))

def process_json(json_file):
    try:
        print_header() 

        with open(json_file, "r", encoding="utf-8") as file:
            content = file.read()

        uid_password_pairs = extract_uid_password(content)

        if not uid_password_pairs:
            console.print("[bold red]❌ Error: No valid UID and Password found.[/bold red]")
            return

        total_uids = len(uid_password_pairs)
        tokens = []
        table = Table(title="🚀 Token Retrieval Status", style="bold cyan")
        table.add_column("UID", style="yellow", justify="center")
        table.add_column("Status", style="green", justify="center")

        with Progress(
            TextColumn("[bold cyan]Processing...[/bold cyan]"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
        ) as progress:

            task = progress.add_task("Fetching Tokens", total=total_uids)

            for uid, password in uid_password_pairs:
                url = API_URL.format(uid, password)
                try:
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        try:
                            response_data = response.json()
                            if "token" in response_data:
                                tokens.append({"token": response_data["token"]}) 
                                table.add_row(uid, "[bold green]✅ Success[/bold green]")
                            else:
                                table.add_row(uid, "[bold red]❌ No Token[/bold red]")
                        except json.JSONDecodeError:
                            table.add_row(uid, "[bold red]❌ Invalid JSON Response[/bold red]")
                    else:
                        table.add_row(uid, f"[bold red]❌ API Error {response.status_code}[/bold red]")
                except requests.Timeout:
                    table.add_row(uid, "[bold yellow]⏳ Timeout[/bold yellow]")
                except requests.RequestException as e:
                    table.add_row(uid, f"[bold red]🚨 Request Error[/bold red]")

                progress.update(task, advance=1)  

        console.print(table)

        if tokens:
            output_file = generate_random_filename(os.path.dirname(json_file))
            with open(output_file, "w", encoding="utf-8") as outfile:
                json.dump(tokens, outfile, indent=4, ensure_ascii=False)

            console.print(Panel(f"📂 Tokens saved to: [bold green]{output_file}[/bold green]", style="bold magenta"))

    except FileNotFoundError:
        console.print("[bold red]❌ Error: File not found. Please provide a valid path.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]❌ Unexpected Error: {e}[/bold red]")

if __name__ == "__main__":
    print_header()
    json_path = console.input("[bold cyan]Enter JSON file path: [/bold cyan]").strip()
    process_json(json_path)
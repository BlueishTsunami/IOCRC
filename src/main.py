# External Imports
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel

# Internal Imports
from apis.shodan import shodan_scan
from apis.virustotal import virustotal_scan
from apis.greynoise import greynoise_scan
import utils.keyring_manager as keyring_manager
from utils.validator import validate_input

# Initialize console and app
console = Console()
app = typer.Typer(
	help="IOCRC - Indicator of Compromise Reputation Checker\n\nA tool for scanning and analyzing security indicators across multiple services.",
	no_args_is_help=True
)

# Create command groups
scan = typer.Typer(
	help="Commands for scanning indicators across different services",
	no_args_is_help=True
)
app.add_typer(scan, name="scan")
app.add_typer(keyring_manager.app, name="key", help="Manage API keys for different services")

@scan.command("full")
def fullscan() -> None:
	"""Execute a comprehensive scan using all available services.

	This command will:
	- Validate the input IOC
	- Run it through all configured scanning services
	- Display consolidated results
	"""
	ioc: str = typer.prompt("Enter an IOC to scan", type=str)
	ioc_type: str = validate_input(ioc)
	
	console.print(Panel.fit("Starting full scan...", style="bold blue"))
	
	# Run appropriate scans based on IOC type
	if ioc_type == "IP":
		shodan_scan(ioc)
		greynoise_scan(ioc)
	virustotal_scan(ioc, ioc_type)

@scan.command("vt")
def vt_scan() -> None:
	"""Execute a VirusTotal scan.

	This command will:
	- Validate the input IOC
	- Query the VirusTotal API
	- Display detailed threat intelligence results
	"""
	ioc: str = typer.prompt("Enter an IOC for VirusTotal", type=str)
	ioc_type: str = validate_input(ioc)
	virustotal_scan(ioc, ioc_type)

@scan.command("shodan")
def shodan_lookup() -> None:
	"""Execute a Shodan-specific lookup.

	This command will:
	- Validate the input IOC (IP address)
	- Query the Shodan API
	- Display detailed host and service information
	"""
	ioc: str = typer.prompt("Enter an IP address for Shodan", type=str)
	validate_input(ioc)
	shodan_scan(ioc)

@scan.command("greynoise")
def greynoise_lookup() -> None:
	"""Execute a GreyNoise-specific lookup.

	This command will:
	- Validate the input IOC (IP address)
	- Query the GreyNoise API
	- Display detailed IP reputation information
	"""
	ioc: str = typer.prompt("Enter an IP address for GreyNoise", type=str)
	validate_input(ioc)
	greynoise_scan(ioc)

# @key.command()
# def remove():
# 	setapikey()

# @key.command()
# def list():
# 	setapikey()

# Only run app() if the script is being executed directly. 
if __name__ == "__main__":
	app()
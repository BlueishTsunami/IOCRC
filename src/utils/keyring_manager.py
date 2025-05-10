import keyring
import typer
import yaml
from pathlib import Path

SERVICES_YAML = Path(__file__).resolve().parent.parent.parent / "config" / "services.yaml"
SERVICE_LIST = ["shodan","virustotal"]

def load_services():
	try:
		with open(SERVICES_YAML, "r") as f:
			return yaml.safe_load(f) or {}
	except FileNotFoundError:
		return {}
	
def save_services(services: dict):
	with open(SERVICES_YAML, "w") as f:
		yaml.safe_dump(services, f)

def setapikey():
	"""Stores an API key in your system's keyring."""
	print("Set your API keys. This will add them to your OS keychain via keyring.")

	# Display options and get choice
	print("\nChoose a service:")
	for i, service in enumerate(SERVICE_LIST, 1):
		print(f"{i}: {service}")
	
	while True:
		try:
			choice = int(typer.prompt("Enter the number of the service"))
			keyname = SERVICE_LIST[choice - 1]
			print(f"You've chosen '{keyname}'")
			break
		except (ValueError, IndexError):
			print("Invalid selection. Please enter a number from the list.")
			
	apikey = typer.prompt(f"Enter your API key for {keyname}").strip()
	keyring.set_password(keyname, "api_key", apikey)
	
	# Open up service.yaml and update with new key
	services = load_services()
	services[keyname] = "api_key"
	save_services(services)

	print(f"API key for '{keyname}' stored successfully.")
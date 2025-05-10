import keyring
import yaml
from pathlib import Path

SERVICES_YAML = Path(__file__).resolve().parent.parent.parent / "config" / "services.yaml"

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
	keyname = input("Enter the name of the service: ").strip().lower()
	apikey = input("Enter your API key: ").strip()
	keyring.set_password(keyname, "api_key", apikey)
	
	# Open up service.yaml and update with new key
	services = load_services()
	services[keyname] = "api_key"
	save_services(services)

	print(f"API key for '{keyname}' stored successfully.")
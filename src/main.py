import keyring
import requests
import shodan
import json
import typer
import yaml

app = typer.Typer()
SERVICES_YAML = "config/services.yaml"

def load_services():
	try:
		with open(SERVICES_YAML, "r") as f:
			return yaml.safe_load(f) or {}
	except FileNotFoundError:
		return {}
	
def save_services(services: dict):
	with open(SERVICES_YAML, "w") as f:
		yaml.safe_dump(services, f)

@app.command()
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


# Virustotal API 
@app.command()
def vtapi():
	"""Queries VirusTotal for info about an IP."""
	ioc = input("Enter an IP: ").strip()
	vt_key = keyring.get_password("virustotal", "api_key")
	if not vt_key:
		print("Error: No VirusTotal API key found. Run 'setapikey' first.")
		return

	url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
	headers = {
		"accept": "application/json",
		"x-apikey": vt_key
	}

	vt_output = requests.get(url, headers=headers)
	vt_json = vt_output.json()
	print(json.dumps(vt_json, indent=2))

# Shodan API
def shodanAPI():
	SHODAN_KEY = keyring.get_password("shodan", "api_key")
	ioc = input("Enter an IP: ")
	api = shodan.Shodan(SHODAN_KEY)
	# Lookup the host
	host = api.host(ioc)

		# Print general info
	print("""
		IP: {}
		Organization: {}
		Operating System: {}
	""".format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

	# Print all banners
	for item in host['data']:
		print("""
			Port: {}
			Banner: {}

		""".format(item['port'], item['data']))

# Only run app() if the script is being executed directly. 
if __name__ == "__main__":
	app()
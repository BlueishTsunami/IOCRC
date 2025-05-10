import json
import keyring
import requests

# Virustotal API 
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
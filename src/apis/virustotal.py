# import json
import keyring
import requests
#from utils.validator import validate_input
from pprint import pprint
from rich.console import Console
from rich.table import Table

net_fields = [
	{"label": "Last Analysis Stats", "field": "last_analysis_stats", "fallback": "N/A"},
	{"label": "Owner", "field": "as_owner", "fallback": "N/A"},
	{"label": "Network / ASN", "field": "network", "additional_field": "asn", "fallback": "N/A"},
	# {"label": "Certificate Issuer", "field": "last_https_certificate.issuer", "fallback": "N/A"},
	# {"label": "Certificate Validity", "field": "last_https_certificate.validity", "fallback": "N/A"},
	# {"label": "cert", "field": "last_https_certificate.validity", "fallback": "N/A"},
	{"label": "Last Scanned", "field": "last_analysis_date", "fallback": "N/A"},
]

file_fields = [
	{"label": "Filename", "field": "meaningful_name", "fallback": "N/A"},
	{"label": "Type", "field": "type_description", "fallback": "N/A"},
	{"label": "Last Analysis Stats", "field": "last_analysis_stats", "fallback": "N/A"},
	{"label": "First Seen", "field": "first_seen_itw_date", "fallback": "N/A"},
	{"label": "Last Scanned", "field": "last_analysis_date", "fallback": "N/A"},
]

# Virustotal API call
def vtapi(ioc, ioc_type):
	"""Queries VirusTotal for info about an IP."""
	vt_key = keyring.get_password("virustotal", "api_key")
	if not vt_key:
		print("Error: No VirusTotal API key found. Run 'setkey' first.")
		return

	if ioc_type == "IP":
		url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
		headers = {
			"accept": "application/json",
			"x-apikey": vt_key
		}
	elif ioc_type == "Hash": 
		url = f"https://www.virustotal.com/api/v3/files/{ioc}"
		headers = {
			"accept": "application/json",
			"x-apikey": vt_key
		}
	elif ioc_type == "Domain": 
		url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
		headers = {
			"accept": "application/json",
			"x-apikey": vt_key
		}
	elif ioc_type == "URL": 
		print("URL API in progress")
		return
	
	vt_output = requests.get(url, headers=headers)
	vt_json = vt_output.json()

	console = Console()
	

	vt_table = Table(title="VirusTotal Report")
	vt_table.add_column("Field", style="orange_red1", no_wrap=True)
	vt_table.add_column("Value", style="red1")

	vt_table.add_row("Type",ioc_type)
	vt_table.add_row("Type",ioc)

	

	if ioc_type != "Hash":
		data = vt_json["data"]["attributes"]
		for field in net_fields:
			
			label_value = field["label"]
			if "additional_field" in field:
				field_value = f"{data.get(field['field'], field['fallback'])}, {data.get(field['additional_field'], field['fallback'])}"
			else:
				field_value = data.get(field["field"])
			
			vt_table.add_row(label_value, str(field_value))
	elif ioc_type == "Hash":
		data = vt_json["data"]["attributes"]
		for field in file_fields:
			
			label_value = field["label"]
			if "additional_field" in field:
				field_value = f"{data.get(field['field'], field['fallback'])}, {data.get(field['additional_field'], field['fallback'])}"
			else:
				field_value = data.get(field["field"])
			
			vt_table.add_row(label_value, str(field_value))
	else:
		pprint(vt_json)
	console.print(vt_table)


	

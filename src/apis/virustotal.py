# import json
import keyring
import requests
#from utils.validator import validate_input
from pprint import pprint
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

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

def display_error(message: str, help_text: str = None) -> None:
	"""Display an error message in a consistent format.
	
	Args:
		message: The main error message
		help_text: Optional help text for resolving the error
	"""
	error_text = Text()
	error_text.append("Error: ", style="bold red")
	error_text.append(message)
	
	if help_text:
		error_text.append("\n\nTip: ", style="bold yellow")
		error_text.append(help_text)
	
	console.print(Panel(error_text, title="VirusTotal Error", border_style="red"))

def virustotal_scan(ioc: str, ioc_type: str) -> None:
	"""Queries VirusTotal for info about an IOC."""
	# Check for API key
	vt_key = keyring.get_password("virustotal", "api_key")
	if not vt_key:
		display_error(
			"No VirusTotal API key found.",
			"Run 'iocrc key set' to configure your API key"
		)
		return

	# Determine endpoint based on IOC type
	if ioc_type == "IP":
		url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
	elif ioc_type == "Hash": 
		url = f"https://www.virustotal.com/api/v3/files/{ioc}"
	elif ioc_type == "Domain": 
		url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
	elif ioc_type == "URL": 
		display_error("URL scanning is not yet implemented")
		return
	else:
		display_error(f"Unsupported IOC type: {ioc_type}")
		return

	headers = {
		"accept": "application/json",
		"x-apikey": vt_key
	}

	try:
		# Make API request
		response = requests.get(url, headers=headers)
		
		# Check for common HTTP errors
		if response.status_code == 401:
			display_error(
				"Invalid API key",
				"Please check your API key and run 'iocrc key set' to update it"
			)
			return
		elif response.status_code == 429:
			display_error(
				"API rate limit exceeded",
				"Please wait a moment before trying again"
			)
			return
		elif response.status_code != 200:
			display_error(
				f"API request failed with status code {response.status_code}",
				f"Response: {response.text[:100]}..."
			)
			return

		# Parse JSON response
		try:
			vt_json = response.json()
		except ValueError:
			display_error(
				"Invalid JSON response from VirusTotal",
				f"Response: {response.text[:100]}..."
			)
			return

		# Validate response structure
		if "data" not in vt_json or "attributes" not in vt_json["data"]:
			display_error(
				"Unexpected API response format",
				"The API response is missing required fields"
			)
			return

		# Create results table
		vt_table = Table(title="VirusTotal Report")
		vt_table.add_column("Field", style="orange_red1", no_wrap=True)
		vt_table.add_column("Value", style="red1")

		vt_table.add_row("Type", ioc_type)
		vt_table.add_row("IOC", ioc)

		data = vt_json["data"]["attributes"]
		fields = file_fields if ioc_type == "Hash" else net_fields

		for field in fields:
			label_value = field["label"]
			try:
				if "additional_field" in field:
					field_value = f"{data.get(field['field'], field['fallback'])}, {data.get(field['additional_field'], field['fallback'])}"
				else:
					field_value = data.get(field["field"], field["fallback"])
				vt_table.add_row(label_value, str(field_value))
			except Exception as e:
				vt_table.add_row(label_value, "Error retrieving value")

		console.print(vt_table)

	except requests.exceptions.RequestException as e:
		display_error(
			"Network error while contacting VirusTotal",
			f"Error: {str(e)}"
		)


	

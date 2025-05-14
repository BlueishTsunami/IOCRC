import requests
from rich.console import Console
from rich.table import Table
from typing import Dict, Any, Optional, Union, List
from utils.api_utils import get_api_key, display_error, create_result_table, handle_api_response
from utils.validator import validate_input, validate_api_input

# Initialize rich console for formatted output
console = Console()

# Define API requirements
API_NAME = "VirusTotal"
VALID_TYPES: List[str] = ["IP", "Domain", "Hash", "URL"]
ERROR_MESSAGE = "VirusTotal accepts IPs, domains, hashes, and URLs"

# Define fields to display for network-related IOCs (IPs and domains)
network_fields = [
	{"label": "Last Analysis Stats", "field": "last_analysis_stats", "fallback": "N/A"},
	{"label": "Reputation", "field": "reputation", "fallback": "N/A"},
	{"label": "Categories", "field": "categories", "fallback": "N/A", "combine": True},
	{"label": "Tags", "field": "tags", "fallback": "N/A", "combine": True},
	{"label": "Network", "field": "network", "fallback": "N/A"},
	{"label": "ASN", "field": "asn", "fallback": "N/A"},
	{"label": "AS Owner", "field": "as_owner", "fallback": "N/A"},
	{"label": "Country", "field": "country", "fallback": "N/A"},
]

# Define fields to display for file-related IOCs (hashes)
file_fields = [
	{"label": "Type", "field": "type_tag", "fallback": "N/A"},
	{"label": "Size", "field": "size", "fallback": "N/A"},
	{"label": "First Submission", "field": "first_submission_date", "fallback": "N/A"},
	{"label": "Last Analysis Stats", "field": "last_analysis_stats", "fallback": "N/A"},
	{"label": "Tags", "field": "tags", "fallback": "N/A", "combine": True},
	{"label": "Names", "field": "names", "fallback": "N/A", "combine": True},
	{"label": "Type Description", "field": "type_description", "fallback": "N/A"},
]

def handle_vt_response(
		vt_response_data: Dict[str, Any],
		ioc: str, 
		ioc_type: str, 
		raw_output: bool = False
		) -> Optional[Dict[str, Any]]:
	"""Handle successful VirusTotal API response.
	
	Args:
		vt_response_data: API response data
		ioc: The IOC that was queried
		ioc_type: Type of the IOC (IP, Domain, Hash, URL)
		raw_output: If True, return raw response data instead of displaying tables
		
	Returns:
		Raw response data if raw_output is True, None otherwise
	"""
	if raw_output:
		return vt_response_data

	# Validate response structure
	if not isinstance(vt_response_data, dict) or "data" not in vt_response_data or "attributes" not in vt_response_data["data"]:
		display_error(
			"Invalid response format",
			"Unexpected response structure from VirusTotal",
			API_NAME
		)
		return None

	# Create detailed results table based on IOC type
	if ioc_type in ["IP", "Domain"]:
		result_table = create_result_table("VirusTotal Network Information", network_fields, vt_response_data["data"]["attributes"])
	else:  # Hash
		result_table = create_result_table("VirusTotal File Information", file_fields, vt_response_data["data"]["attributes"])
	console.print("\n")
	console.print(result_table)
	return None

def virustotal_scan(ioc: str, ioc_type: str, raw_output: bool = False) -> Optional[Dict[str, Any]]:
	"""Queries VirusTotal for information about an IOC.
	
	Args:
		ioc: IOC to query (IP, domain, hash, or URL)
		ioc_type: Type of the IOC
		raw_output: If True, return raw response data instead of displaying tables
		
	Returns:
		Raw response data if raw_output is True, None otherwise
	"""
	# Validate input 
	is_valid, error_message = validate_api_input(ioc, API_NAME, VALID_TYPES, ERROR_MESSAGE)
	if not is_valid:
		display_error("Invalid input", error_message, API_NAME)
		return None

	# Get API key from keyring
	vt_key = get_api_key("virustotal")
	if not vt_key:
		display_error(
			"No VirusTotal API key found",
			"Run 'iocrc key set' to configure your API key",
			API_NAME
		)
		return None

	# Set up API request based on IOC type
	if ioc_type == "IP":
		api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
	elif ioc_type == "Domain":
		api_url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
	elif ioc_type == "Hash":
		api_url = f"https://www.virustotal.com/api/v3/files/{ioc}"
	elif ioc_type == "URL":
		# URL scanning not implemented yet
		display_error(
			"Unsupported IOC type",
			"URL scanning is not yet implemented",
			API_NAME
		)
		return None
	else:
		display_error(
			"Invalid IOC type",
			f"Unsupported IOC type: {ioc_type}",
			API_NAME
		)
		return None

	headers = {
		"x-apikey": vt_key,
		"Accept": "application/json"
	}

	try:
		# Make API request and handle response
		response = requests.get(api_url, headers=headers)
		return handle_api_response(
			response,
			lambda vt_response_data: handle_vt_response(vt_response_data, ioc, ioc_type, raw_output),
			API_NAME
		)
	except requests.exceptions.RequestException as e:
		# Handle network-related errors
		display_error(
			"Network error while contacting VirusTotal",
			f"Error: {str(e)}",
			API_NAME
		)
		return None


	

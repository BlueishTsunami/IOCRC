import requests
from typing import Dict, Any, Optional, List
from rich.console import Console
from rich.table import Table
from utils.api_utils import get_api_key, display_error, create_result_table, handle_api_response
from utils.validator import validate_api_input

# Initialize rich console for formatted output
console = Console()

# Define API requirements
API_NAME = "Shodan"
VALID_TYPES: List[str] = ["IP"]
ERROR_MESSAGE = "Shodan only accepts IP addresses as input"

# Define fields to display for host information
host_fields = [
	{"label": "Organization", "field": "org", "fallback": "N/A"},
	{"label": "Operating System", "field": "os", "fallback": "N/A"},
	{"label": "Country", "field": "country_name", "fallback": "N/A"},
	{"label": "City", "field": "city", "fallback": "N/A"},
	{"label": "ISP", "field": "isp", "fallback": "N/A"},
	{"label": "Last Updated", "field": "last_update", "fallback": "N/A"},
	{"label": "Open Ports", "field": "ports", "fallback": "N/A", "combine": True},
	{"label": "Hostnames", "field": "hostnames", "fallback": "N/A", "combine": True},
	#{"label": "Vulns", "field": "vulns", "fallback": "N/A", "combine": True},
]

def create_services_table(services: list) -> Table:
	"""Create a table displaying services information.
	
	Args:
		services: List of services to display
		
	Returns:
		Rich Table object containing service information
	"""
	services_table = Table(title="Shodan Services")
	services_table.add_column("Port", style="cyan")
	services_table.add_column("Service", style="green")
	services_table.add_column("Product", style="green")
	services_table.add_column("Version", style="green")
	services_table.add_column("Vulns", style="red")
	services_table.add_column("Banner", style="yellow")

	for service in services:
		# Extract banner and truncate if too long
		banner = service.get("data", "N/A")
		if isinstance(banner, str):
			banner = banner.replace("\n", " ")[:100]  # Truncate long banners

		# Get vulnerabilities if available
		vulns = service.get("vulns", [])
		vulns_str = ", ".join(vulns) if vulns else "N/A"

		services_table.add_row(
			str(service.get("port", "N/A")),
			service.get("name", "N/A"),
			service.get("product", service.get("module", "N/A")),  # Use product or module name
			service.get("version", "N/A"),
			vulns_str,
			banner
		)

	return services_table

def handle_shodan_response(response_data: Dict[str, Any], raw_output: bool = False) -> Optional[Dict[str, Any]]:
	"""Handle successful Shodan API response.
	
	Args:
		response_data: API response data
		raw_output: If True, return raw response data instead of displaying tables
		
	Returns:
		Raw response data if raw_output is True, None otherwise
	"""
	if raw_output:
		return response_data

	# Validate response structure
	if not isinstance(response_data, dict):
		display_error(
			"Invalid response format",
			"Unexpected response structure from Shodan",
			API_NAME
		)
		return None

	# Create and display host information table
	result_table = create_result_table("Shodan Host Report", host_fields, response_data)
	console.print(result_table)

	# Display services if available
	if response_data.get("data"):
		console.print("\n")
		console.print(create_services_table(response_data["data"]))

	# Display vulnerabilities if available
	# if response_data.get("vulns"):
	# 	vulns_table = Table(title="Vulnerabilities")
	# 	vulns_table.add_column("CVE", style="red")
	# 	vulns_table.add_column("Summary", style="yellow")
		
	# 	for vuln in response_data["vulns"]:
	# 		vulns_table.add_row(
	# 			vuln,
	# 			response_data.get("vulns", {}).get(vuln, {}).get("summary", "N/A")
	# 		)
		
	# 	console.print("\n")
	# 	console.print(vulns_table)

	# return None

def shodan_scan(ip: str, raw_output: bool = False) -> Optional[Dict[str, Any]]:
	"""Queries Shodan for information about an IP address.
	
	Args:
		ip: IP address to query
		raw_output: If True, return raw response data instead of displaying tables
		
	Returns:
		Raw response data if raw_output is True, None otherwise
	"""
	# Validate input using the new validation function
	is_valid, error_message = validate_api_input(ip, API_NAME, VALID_TYPES, ERROR_MESSAGE)
	if not is_valid:
		display_error("Invalid input", error_message, API_NAME)
		return None

	# Get API key from keyring
	shodan_key = get_api_key("shodan")
	if not shodan_key:
		display_error(
			"No Shodan API key found",
			"Run 'iocrc key set' to configure your API key",
			API_NAME
		)
		return None

	# Set up API request
	host_api_url = f"https://api.shodan.io/shodan/host/{ip}"
	params = {"key": shodan_key}

	try:
		# Make API request and handle response
		response = requests.get(host_api_url, params=params)
		return handle_api_response(
			response,
			lambda response_data: handle_shodan_response(response_data, raw_output),
			API_NAME
		)
	except requests.exceptions.RequestException as e:
		# Handle network-related errors
		display_error(
			"Network error while contacting Shodan",
			f"Error: {str(e)}",
			API_NAME
		)
		return None
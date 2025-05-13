import shodan
import keyring
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

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
	
	console.print(Panel(error_text, title="Shodan Error", border_style="red"))

def shodan_scan(ioc: str) -> None:
	"""Queries Shodan for info about an IP."""
	# Check for API key
	shodan_key = keyring.get_password("shodan", "api_key")
	if not shodan_key:
		display_error(
			"No Shodan API key found",
			"Run 'iocrc key set' to configure your API key"
		)
		return

	try:
		# Initialize Shodan API
		api = shodan.Shodan(shodan_key)

		try:
			# Lookup the host
			host = api.host(ioc)
		except shodan.APIError as e:
			if "Invalid API key" in str(e):
				display_error(
					"Invalid Shodan API key",
					"Please check your API key and run 'iocrc key set' to update it"
				)
			elif "No information available" in str(e):
				display_error(
					f"No information found for IP: {ioc}",
					"The IP address might not be indexed by Shodan"
				)
			else:
				display_error(
					f"Shodan API error: {str(e)}",
					"Please try again later or check your query"
				)
			return

		# Create results table
		shodan_table = Table(title="Shodan IP Report")
		shodan_table.add_column("Field", style="cyan", no_wrap=True)
		shodan_table.add_column("Value", style="green")

		# Fields to grab from API response
		basic_fields = [
			("IP", host.get('ip_str', 'N/A')),
			("Organization", host.get('org', 'N/A')),
			("Operating System", host.get('os', 'N/A')),
			("Country", host.get('country_name', 'N/A')),
			("City", host.get('city', 'N/A')),
			("ISP", host.get('isp', 'N/A')),
			("Last Updated", host.get('last_update', 'N/A')),
			("Open Ports", ', '.join(map(str, host.get('ports', []))) or 'N/A')
		]

		for field, value in basic_fields:
			shodan_table.add_row(field, str(value))

		console.print(shodan_table)

		# Create services table if there are any
		if host.get('data'):
			services_table = Table(title="Shodan Open Services Report")
			services_table.add_column("Port", style="cyan", no_wrap=True)
			services_table.add_column("Service", style="green")
			services_table.add_column("Banner", style="green")

			for item in host['data']:
				port = str(item.get('port', 'N/A'))
				service = item.get('product', item.get('module', 'N/A'))
				banner = item.get('data', 'N/A').replace('\n', ' ')[:100]  # Truncate long banners
				services_table.add_row(port, service, banner)

			console.print("\n")  # Add spacing between tables
			console.print(services_table)

	except shodan.APIError as e:
		display_error(
			"Shodan API error occurred",
			f"Error: {str(e)}"
		)
	except Exception as e:
		display_error(
			"An unexpected error occurred",
			f"Error: {str(e)}"
		)
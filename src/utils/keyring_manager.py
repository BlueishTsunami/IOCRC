import keyring
import typer
# import yaml
# from pathlib import Path
from typing import Optional

app = typer.Typer()

SERVICE_LIST = ["shodan","virustotal"]

def list_configured_services():
	return [s for s in SERVICE_LIST if keyring.get_password(s, "api_key")]

# Set an API key for a service
@app.command()
def set(service: Optional[str] = typer.Option(None, help="Service to set API key for", metavar="SERVICE")):
	"""Stores an API key in your system's keyring."""
	print("Set your API keys. This will add them to your OS keychain via keyring.")

	# If service is provided via command line, use it directly
	if service and service in SERVICE_LIST:
		keyname = service
	else:
		# Display interactive service selection menu
		print("\nChoose a service:")
		for i, service in enumerate(SERVICE_LIST, 1):
			print(f"{i}: {service}")
		
		# Get and validate user's service selection
		while True:
			try:
				choice = int(typer.prompt("Enter the number of the service"))
				keyname = SERVICE_LIST[choice - 1]
				print(f"You've chosen '{keyname}'")
				break
			except (ValueError, IndexError):
				print("Invalid selection. Please enter a number from the list.")
			
	# Get API key and store it securely
	apikey = typer.prompt(f"Enter your API key for {keyname}", hide_input=True).strip()
	keyring.set_password(keyname, "api_key", apikey)

	print(f"API key for '{keyname}' stored successfully.")

# Edit an existing API key
@app.command()
def edit(service: Optional[str] = typer.Option(None, help="Service to edit API key for", metavar="SERVICE")):
	"""Edit an existing API key."""
	# Get list of services that have stored API keys
	services = list_configured_services()
	if not services:
		print("No API keys found to edit.")
		return
	
	# If service is provided via command line, use it directly
	if service and service in services:
		keyname = service
	else:
		# Display interactive service selection menu
		print("\nStored services:")
		for i, service in enumerate(services, 1):
			print(f"{i}: {service}")

		# Get and validate user's service selection
		while True:
			try:
				choice = int(typer.prompt("Enter the number of the service"))
				keyname = services[choice - 1]
				print(f"You've chosen '{keyname}'")
				break
			except (ValueError, IndexError):
				print("Invalid selection. Please enter a number from the list.")

	# Enter new key and save to keychain via keyring. 
	new_apikey = typer.prompt(f"Enter the new API key for {keyname}", hide_input=True).strip()
	keyring.set_password(keyname, "api_key", new_apikey)

	print(f"API key for '{keyname}' updated successfully.")

# List existing API keys
@app.command()
def list():
	"""List existing API key(s)."""
	# Get list of services that have stored API keys
	services = list_configured_services()
	if not services:
		print("No API keys found to list.")
		return
	
	# Display numbered list of configured services
	print("\nStored services:")
	for i, service in enumerate(services, 1):
		print(f"{i}: {service}")
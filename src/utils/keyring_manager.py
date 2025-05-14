import os
import keyring
import typer
# import yaml
# from pathlib import Path
from typing import Optional

app = typer.Typer()

def get_available_services():
	"""Get list of available services from the apis directory."""
	# Get the directory containing this file
	current_dir = os.path.dirname(os.path.abspath(__file__))
	# Go up one level to src directory
	src_dir = os.path.dirname(current_dir)
	# Path to apis directory
	apis_dir = os.path.join(src_dir, "apis")
	
	# Get all .py files in the apis directory
	services = []
	for filename in os.listdir(apis_dir):
		if filename.endswith(".py") and filename != "__init__.py" and filename != "template_api.py":
			# Remove .py extension and convert to lowercase
			service_name = filename[:-3].lower()
			services.append(service_name)
	
	return sorted(services)

def list_configured_services():
	return [s for s in get_available_services() if keyring.get_password(s, "api_key")]

# Set an API key for a service
@app.command()
def set(service: Optional[str] = typer.Option(None, help="Service to set API key for", metavar="SERVICE")):
	"""Stores an API key in your system's keyring."""
	print("Set your API keys. This will add them to your OS keychain via keyring.")

	# Get available services
	SERVICE_LIST = get_available_services()

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
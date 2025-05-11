import keyring
import typer
import yaml
from pathlib import Path

app = typer.Typer()

SERVICE_LIST = ["shodan","virustotal"]

def list_configured_services():
	return [s for s in SERVICE_LIST if keyring.get_password(s, "api_key")]

@app.command()
def set():
	"""Stores an API key in your system's keyring."""
	print("Set your API keys. This will add them to your OS keychain via keyring.")

	# Display options and get choice
	print("\nChoose a service:")
	for i, service in enumerate(SERVICE_LIST, 1):
		print(f"{i}: {service}")
	
	while True:
		try:
			choice = int(typer.prompt("Enter the number of the service"))
			keyname = SERVICE_LIST[choice - 1]
			print(f"You've chosen '{keyname}'")
			break
		except (ValueError, IndexError):
			print("Invalid selection. Please enter a number from the list.")
			
	apikey = typer.prompt(f"Enter your API key for {keyname}").strip()
	keyring.set_password(keyname, "api_key", apikey)

	print(f"API key for '{keyname}' stored successfully.")

@app.command()
def edit():
	"""Edit an existing API key."""
	# Set file to variable and check for validity
	services = list_configured_services()
	if not services:
		print("No API keys found to edit.")
		return
	
	# Print services.yaml
	print("\nStored services:")
	for i, service in enumerate(services, 1):
		print(f"{i}: {service}")

	# User input for service to change and set to index in the list. 
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

@app.command()
def list():
	
	"""List existing API key(s)."""
	# Set file to variable and check for validity
	services = list_configured_services()
	if not services:
		print("No API keys found to list.")
		return
	
	# Print services.yaml
	print("\nStored services:")
	for service in enumerate(services, 1):
		print(f"Service: {service}")
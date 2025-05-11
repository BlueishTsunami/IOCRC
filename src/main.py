import typer
from apis.shodan import shodanapi
from apis.virustotal import vtapi
import utils.keyring_manager as keyring_manager
from utils.validator import validate_input


app = typer.Typer()
app.add_typer(keyring_manager.app, name="key")

def test(name: str):
	print(f"hello {name}")

@app.command()
def fullscan():
	ioc = typer.prompt("Enter an IP address to scan: ", type=str)
	validate_input(ioc)
	shodanapi(ioc)
	vtapi(ioc)

@app.command()
def vt():
	ioc = typer.prompt("Enter an IP address for VirusTotal: ", type=str)
	validate_input(ioc)
	vtapi(ioc)

@app.command()
def shodan():
	ioc = typer.prompt("Enter an IP address for Shodan: ", type=str)
	validate_input(ioc)
	shodanapi(ioc)

@app.command()
def setkey():
	setapikey()

# Only run app() if the script is being executed directly. 
if __name__ == "__main__":
	app()
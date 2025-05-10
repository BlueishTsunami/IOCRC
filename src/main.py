import typer
from src.apis.shodan import shodanapi
from src.apis.virustotal import vtapi
from src.utils.keyring_manager import setapikey


app = typer.Typer()

@app.command()
def fullscan():
	ioc = typer.prompt("Enter an IP address to scan: ", type=str)
	shodanapi(ioc)
	vtapi(ioc)

@app.command()
def vt():
	ioc = typer.prompt("Enter an IP address for VirusTotal: ", type=str)
	vtapi(ioc)

@app.command()
def shodan():
	ioc = typer.prompt("Enter an IP address for Shodan: ", type=str)
	shodanapi(ioc)

@app.command()
def setkey():
	setapikey()

# Only run app() if the script is being executed directly. 
if __name__ == "__main__":
	app()
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
	ioc = typer.prompt("Enter an IOC to scan: ", type=str)
	validate_input(ioc)
	shodanapi(ioc)
	vtapi(ioc)

@app.command()
def vt():
	ioc = typer.prompt("Enter an IOC for VirusTotal: ", type=str)
	ioc_type = validate_input(ioc)
	vtapi(ioc, ioc_type)

@app.command()
def shodan():
	ioc = typer.prompt("Enter an IOC for Shodan: ", type=str)
	validate_input(ioc)
	shodanapi(ioc)



# @key.command()
# def remove():
# 	setapikey()

# @key.command()
# def list():
# 	setapikey()

# Only run app() if the script is being executed directly. 
if __name__ == "__main__":
	app()
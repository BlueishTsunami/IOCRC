import typer
from apis.shodan import shodanapi
from apis.virustotal import vtapi
from utils.keyring_manager import setapikey

app = typer.Typer()

app.command()(setapikey)
app.command()(vtapi)
app.command()(shodanapi)

# Only run app() if the script is being executed directly. 
if __name__ == "__main__":
	app()
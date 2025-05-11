# IOCRC
IOC Reputation Checker. Basically a bunch of API calls in a trenchcoat. 

Rough goal of this project is to create a tool for easily checking IOC reputation across several sources. Input validation in the program will automatically detect the type of IOC being used, and utilize the appropriate queries. 

So far contains boilerplate API calls for the following: 
- Shodan
- VirusTotal

TODO:
- Continue adding sources
- Clean up outputs and tune sources
- Several output options

Future TODO: 
- Bulk importing IOCs and outputting reports
- Potential web interface using FastAPI

Requires uv to run. While this is still a dev project, do the following to get it running: 

```sh
# Download Source, go to directory, and activate the environment
uv venv .venv
.venv\Scripts\activate

# Build and install the package
uv build
uv pip install -e .

# run it
iocrc --help
iocrc --help

 Usage: iocrc [OPTIONS] COMMAND [ARGS]...

╭─ Commands ────────────────────────────────────────────╮
│ fullscan      # Not running yet                       |
│ vt                                                    |
│ shodan        # Not running yet                       |
│ key                                                   |
╰───────────────────────────────────────────────────────╯
```

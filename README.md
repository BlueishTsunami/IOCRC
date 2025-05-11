# IOCRC
IOC Reputation Checker. Basically a bunch of API calls in a trenchcoat. 

Rough goal of this project is to create a tool for easily checking IOC reputation across several sources. 

So far contains boilerplate API calls for the following: 
- Shodan
- VirusTotal

TODO:
- Continue adding sources
- Clean up outputs and tune sources
- Several output options

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

╭─ Options ──────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --install-completion          Install completion for the current shell.                                        |
│ --show-completion             Show completion for the current shell, to copy it or customize the installation. |
│ --help                        Show this message and exit.                                                      |
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ─────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ fullscan      # Not running yet                                                                                |
│ vt                                                                                                             |
│ shodan        # Not running yet                                                                                |
│ key                                                                                                            |
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

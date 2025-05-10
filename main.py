import keyring
import requests
import shodan
import json

def setapikey():
        print("Set your API keys. This will add them to your OS keychain via keyring")
        keyname = input("Enter the name of the service: ")
        apikey = input("Enter your API key: ")
        keyring.set_password(keyname, "api_key", apikey)


# Virustotal API 
def vtAPI():
        ioc = input("Enter an IP: ")
        VT_KEY = keyring.get_password("virustotal", "api_key")

        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ioc

        headers = {
            "accept": "application/json",
            "x-apikey": VT_KEY
        }

        vt_output = requests.get(url, headers=headers)
        vt_json = vt_output.json()
        print(json.dumps(vt_json, indent=2))

# Shodan API
def shodanAPI():
        SHODAN_KEY = keyring.get_password("shodan", "api_key")
        ioc = input("Enter an IP: ")
        api = shodan.Shodan(SHODAN_KEY)
        # Lookup the host
        host = api.host(ioc)

                # Print general info
        print("""
                IP: {}
                Organization: {}
                Operating System: {}
        """.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

        # Print all banners
        for item in host['data']:
                print("""
                        Port: {}
                        Banner: {}

                """.format(item['port'], item['data']))


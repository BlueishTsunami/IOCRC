import shodan
import keyring

# Shodan API
def shodanapi(ioc):
	"""Queries Shodan for info about an IP."""
	SHODAN_KEY = keyring.get_password("shodan", "api_key")
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
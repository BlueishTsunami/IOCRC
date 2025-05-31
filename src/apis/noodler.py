from utils.api_utils import display_error, get_api_key
import vt

API_NAME = "Noodler"

def noodler_scan() -> None:
    """Queries the template API for information about an IOC.
    
    Args:
        ioc: The IOC to query
        ioc_type: Type of the IOC (IP, Domain, Hash, URL)
        raw_output: If True, return raw response data instead of displaying tables
    """

    # Get API key from keyring
    vt_key = get_api_key("virustotal")
    if not vt_key:
        display_error(
            "No API key found",
            "Run 'iocrc key set' to configure your API key",
            API_NAME
        )
        return

    client = vt.Client(vt_key)
    # file = client.get_object("/files/44d88612fea8a8f36de82e1278abb02f")
    # shahash = file.get("sha256")
    # url_id = vt.url_id("http://www.virustotal.com")
    # url = client.get_object("/urls/{}", url_id)
    it = client.iterator("/files/44d88612fea8a8f36de82e1278abb02f/execution_parents", batch_size=20, limit=200)
    for link in it:
        print(link)
    print(it.cursor)
    # print(url.last_analysis_stats)
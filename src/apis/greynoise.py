import requests
from typing import Dict, Any, Optional, List
from rich.console import Console
from rich.table import Table
from utils.api_utils import get_api_key, display_error, create_result_table, handle_api_response
from utils.validator import validate_api_input

# Initialize rich console for formatted output
console = Console()

# Define API requirements
API_NAME = "GreyNoise"
VALID_TYPES: List[str] = ["IP"]
ERROR_MESSAGE = "GreyNoise only accepts IP addresses as input"

# Define fields to display for IP information
ip_fields = [
    {"label": "Classification", "field": "classification", "fallback": "N/A"},
    {"label": "Last Seen", "field": "last_seen", "fallback": "N/A"},
    {"label": "Name", "field": "name", "fallback": "N/A"},
    {"label": "Link", "field": "link", "fallback": "N/A"},
    {"label": "Noise", "field": "noise", "fallback": "N/A"},
    {"label": "RIOT", "field": "riot", "fallback": "N/A"},
]

def handle_greynoise_response(response_data: Dict[str, Any], ip: str, raw_output: bool = False) -> Optional[Dict[str, Any]]:
    """Handle successful GreyNoise API response.
    
    Args:
        response_data: API response data
        ip: The IP address that was queried
        raw_output: If True, return raw response data instead of displaying tables
        
    Returns:
        Raw response data if raw_output is True, None otherwise
    """
    if raw_output:
        return response_data
    
    # Validate response structure
    if "data" not in response_data or "attributes" not in response_data["data"]:
        display_error(
            "Unexpected API response format",
            "The API response is missing required fields",
            API_NAME
        )
        return

    # Create and display IP information table
    result_table = create_result_table("GreyNoise IP Report", ip_fields, response_data["data"]["attributes"])
    
    # Display the table
    console.print(result_table)

    # ---- End of Template API, start of GreyNoise specific code ----

    # Display tags if available
    if response_data.get("tags"):
        tags_table = Table(title="GreyNoise Tags")
        tags_table.add_column("Tag", style="cyan")
        tags_table.add_column("Category", style="green")
        tags_table.add_column("Description", style="green")

        for tag in response_data["tags"]:
            tags_table.add_row(
                tag.get("name", "N/A"),
                tag.get("category", "N/A"),
                tag.get("description", "N/A")
            )
        console.print("\n")
        console.print(tags_table)

    return None

def greynoise_scan(ip: str, raw_output: bool = False) -> Optional[Dict[str, Any]]:
    """Queries GreyNoise for information about an IP address.
    
    Args:
        ip: IP address to query
        raw_output: If True, return raw response data instead of displaying tables
        
    Returns:
        Raw response data if raw_output is True, None otherwise
    """
    # Validate input using validator.py validation function
    is_valid, error_message = validate_api_input(ip, API_NAME, VALID_TYPES, ERROR_MESSAGE)
    if not is_valid:
        display_error("Invalid input", error_message, API_NAME)
        return None

    # Get API key from keyring
    greynoise_key = get_api_key("greynoise")
    if not greynoise_key:
        display_error(
            "No GreyNoise API key found",
            "Run 'iocrc key set' to configure your API key",
            API_NAME
        )
        return None

    # Set up API request
    api_url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {
        "Accept": "application/json",
        "key": greynoise_key
    }

    try:
        # Make API request and handle response
        response = requests.get(api_url, headers=headers)
        return handle_api_response(
            response,
            lambda response_data: handle_greynoise_response(response_data, ip, raw_output),
            API_NAME
        )
    except requests.exceptions.RequestException as e:
        # Handle network-related errors
        display_error(
            "Network error while contacting GreyNoise",
            f"Error: {str(e)}",
            API_NAME
        )
        return None 
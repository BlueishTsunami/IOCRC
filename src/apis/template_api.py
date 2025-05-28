import requests
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from utils.api_utils import get_api_key, display_error, create_result_table, handle_api_response
from utils.validator import validate_api_input

# Initialize rich console for formatted output
console = Console()

API_NAME = "Name of the API"
VALID_INPUTS: List[str] = ["IP", "Domain", "Hash", "URL"]
INPUT_ERROR_MESSAGE = f"{API_NAME} only accepts IP addresses as input"

# Define fields to display in the results table
# Each field should have:
# - label: Display name for the field
# - field: Key to look up in the API response
# - fallback: Value to show if field is not found
# - additional_field: (optional) Additional field to combine with main field
# - transform: (optional) Function to transform the value before display
result_fields = [
    {"label": "Field 1", "field": "field1", "fallback": "N/A"},
    {"label": "Field 2", "field": "field2", "fallback": "N/A"},
    {"label": "Combined Field", "field": "field3", "additional_field": "field4", "fallback": "N/A"},
    {"label": "Transformed Field", "field": "field5", "fallback": "N/A", "transform": lambda x: str(x).upper() if x else "N/A"},
]

def handle_template_api_response(response_data: Dict[str, Any], ioc: str, ioc_type: str, raw_output: bool = False) -> None:
    """Handle successful API response.
    
    Args:
        response_data: API response data
        ioc: The IOC that was queried
        ioc_type: Type of the IOC
        raw_output: If True, return raw response data instead of displaying tables
    """
    
    if raw_output:
        return response_data
    
    # Validate response structure, ensure the checks match expected responses.
    if "data" not in response_data or "attributes" not in response_data["data"]:
        display_error(
            "Unexpected API response format",
            "The API response is missing required fields",
            API_NAME
        )
        return

    # Create results table using the defined fields
    result_table = create_result_table("Template API Report", result_fields, response_data["data"]["attributes"])
    
    # Display the table
    console.print(result_table)


def template_scan(ioc: str, ioc_type: str, raw_output: bool = False) -> None:
    """Queries the template API for information about an IOC.
    
    Args:
        ioc: The IOC to query
        ioc_type: Type of the IOC (IP, Domain, Hash, URL)
        raw_output: If True, return raw response data instead of displaying tables
    """
    # Validate input using validator.py validation function
    is_valid, error_message = validate_api_input(ioc, API_NAME, VALID_INPUTS, INPUT_ERROR_MESSAGE)
    if not is_valid:
        display_error("Invalid input", error_message, API_NAME)
        return None

    # Get API key from keyring
    api_key = get_api_key("template_api")
    if not api_key:
        display_error(
            "No API key found",
            "Run 'iocrc key set' to configure your API key",
            API_NAME
        )
        return

    # Select appropriate API endpoint based on IOC type
    if ioc_type == "IP":
        url = f"https://api.example.com/ip/{ioc}"
    elif ioc_type == "Hash": 
        url = f"https://api.example.com/file/{ioc}"
    elif ioc_type == "Domain": 
        url = f"https://api.example.com/domain/{ioc}"
    elif ioc_type == "URL": 
        url = f"https://api.example.com/url/{ioc}"
    else:
        display_error(f"Unsupported IOC type: {ioc_type}", service_name="Template API")
        return

    # Set up API request headers
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        # Make API request and handle response
        response = requests.get(url, headers=headers)
        handle_api_response(
            response,
            lambda api_results: handle_api_response(api_results, ioc, ioc_type),
            "Template API"
        )
    except requests.exceptions.RequestException as e:
        # Handle network-related errors
        display_error(
            "Network error while contacting API",
            f"Error: {str(e)}",
            "Template API"
        ) 
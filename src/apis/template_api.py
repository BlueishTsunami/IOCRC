import requests
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from utils.api_utils import get_api_key, display_error, create_result_table, handle_api_response
from utils.validator import validate_input

# Initialize rich console for formatted output
console = Console()

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

def handle_api_response(api_results: Dict[str, Any], ioc: str, ioc_type: str) -> None:
    """Handle successful API response.
    
    Args:
        api_results: API response data
        ioc: The IOC that was queried
        ioc_type: Type of the IOC
    """
    # Validate response structure
    if "data" not in api_results or "attributes" not in api_results["data"]:
        display_error(
            "Unexpected API response format",
            "The API response is missing required fields",
            "Template API"
        )
        return

    # Create results table using the defined fields
    result_table = create_result_table("Template API Report", result_fields, api_results["data"]["attributes"])
    
    # Display the table
    console.print(result_table)

def template_scan(ioc: str, ioc_type: str) -> None:
    """Queries the template API for information about an IOC.
    
    Args:
        ioc: The IOC to query
        ioc_type: Type of the IOC (IP, Domain, Hash, URL)
    """
    # Validate input and ensure it matches the provided type
    try:
        if not validate_input(ioc):
            display_error(
                "Input type mismatch",
                f"IOC type {ioc_type} is not supported.",
                "Template API"
            )
            return
    except Exception as e:
        display_error(
            "Invalid input",
            str(e),
            "Template API"
        )
        return

    # Get API key from keyring
    api_key = get_api_key("template_api")
    if not api_key:
        display_error(
            "No API key found",
            "Run 'iocrc key set' to configure your API key",
            "Template API"
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
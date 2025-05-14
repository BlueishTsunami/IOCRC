import keyring
import requests
from typing import Dict, List, Optional, Any, Callable
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# Initialize rich console for formatted output
console = Console()

def get_api_key(service_name: str) -> Optional[str]:
    """Get API key for a service from keyring.
    
    Args:
        service_name: Name of the service to get key for
        
    Returns:
        API key if found, None otherwise
    """
    # Retrieve API key from system keyring
    return keyring.get_password(service_name, "api_key")

def display_error(message: str, help_text: Optional[str] = None, service_name: str = "API") -> None:
    """Display an error message in a consistent format.
    
    Args:
        message: The main error message
        help_text: Optional help text for resolving the error
        service_name: Name of the service for the error title
    """
    # Create formatted error text with bold red "Error:" prefix
    error_text = Text()
    error_text.append("Error: ", style="bold red")
    error_text.append(message)
    
    # Add optional help text with yellow "Tip:" prefix
    if help_text:
        error_text.append("\n\nTip: ", style="bold yellow")
        error_text.append(help_text)
    
    # Display error in a red-bordered panel with service name
    console.print(Panel(error_text, title=f"{service_name} Error", border_style="red"))

def create_result_table(title: str, fields: List[Dict[str, Any]], data: Dict[str, Any]) -> Table:
    """Create a formatted table from API response data.
    
    Args:
        title: Title for the table
        fields: List of field definitions with labels and paths
        data: API response data to extract values from
        
    Returns:
        Formatted Rich table
    """
    # Initialize table with title and columns
    table = Table(title=title)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    
    # Process each field definition
    for field in fields:
        label = field["label"]
        try:
            # Handle fields that need to combine multiple values
            if "additional_field" in field:
                value = f"{data.get(field['field'], field['fallback'])}, {data.get(field['additional_field'], field['fallback'])}"
            else:
                value = data.get(field["field"], field["fallback"])
            table.add_row(label, str(value))
        except Exception:
            # Use fallback text if value can't be retrieved
            table.add_row(label, "Error retrieving value")
            
    return table

def handle_api_response(
    response: requests.Response,
    # Type hint for success_handler, requiring a function that takes a dictionary and returns None
    success_handler: Callable[[Dict[str, Any]], None],
    service_name: str
) -> None:
    """Handle common API response patterns and errors.
    
    Args:
        response: Response from API request
        success_handler: Function to handle successful response
        service_name: Name of the service for error messages
    """
    # Check for common HTTP error codes
    if response.status_code == 401:
        display_error(
            "Invalid API key",
            f"Please check your API key and run 'iocrc key set' to update it",
            service_name
        )
        return
    elif response.status_code == 429:
        display_error(
            "API rate limit exceeded",
            "Please wait a moment before trying again",
            service_name
        )
        return
    elif response.status_code != 200:
        display_error(
            f"API request failed with status code {response.status_code}",
            f"Response: {response.text[:100]}...",
            service_name
        )
        return

    # Parse JSON response
    try:
        data = response.json()
    except ValueError:
        display_error(
            f"Invalid JSON response from {service_name}",
            f"Response: {response.text[:100]}...",
            service_name
        )
        return

    # Call success handler with parsed data
    success_handler(data) 
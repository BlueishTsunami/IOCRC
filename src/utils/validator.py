import re
import ipaddress
from typing import Optional, Dict, List, Tuple
import typer

def validate_input(input_str: str) -> Optional[str]:
    """Validate input string and determine its type.
    
    Args:
        input_str: The input string to validate
        
    Returns:
        String indicating the type of IOC (IP, URL, Domain, Hash) or None if invalid
    """
    # Test cases for regex patterns
    url_pattern = r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    hash_pattern = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'

    # Check if input is a valid IP address
    try:
        ipaddress.ip_address(input_str)
        return "IP"
    except ValueError:
        pass

    # Check if input is a valid URL
    if re.match(url_pattern, input_str):
        return "URL"

    # Check if input is a valid domain
    if re.match(domain_pattern, input_str):
        return "Domain"

    # Check if input is a valid hash
    if re.match(hash_pattern, input_str):
        return "Hash"

    return None

# Validate input for specific API requirements. Returns a tuple of (is_valid, error_message)
def validate_api_input(input_str: str, api_name: str, valid_types: List[str], error_message: str) -> Tuple[bool, Optional[str]]:
    """Validate input for specific API requirements.
    
    Args:
        input_str: The input string to validate
        api_name: Name of the API to validate for
        valid_types: List of valid IOC types for this API
        error_message: Message to display if input type is invalid
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    ioc_type = validate_input(input_str)
    
    if not ioc_type:
        return False, f"Invalid input format for {api_name}"
        
    if ioc_type not in valid_types:
        return False, error_message
        
    return True, None

def test_validation():
    # close-miss test cases for testing the regex
    test_inputs = [
        "999.999.999.999",       # Invalid IPv4
        "256.256.256.256",       # Invalid IPv4 (out of range)
        "http:/incomplete.com",  # Malformed URL
        "ftp:/bad.protocol",     # Malformed URL
        "google",                # Invalid domain (no TLD)
        "example..com",          # Invalid domain (double dot)
        "deadbeef",              # Too short to be hash
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",  # Invalid hex for hash
        "::g:0:0:0",             # Invalid IPv6
        "http://",               # Incomplete URL
        "1234:5678:90ab:cdef:ghij:klmn:opqr:stuv",  # Invalid IPv6 (invalid hex)
    ]

    for ioc in test_inputs:
        try:
            print(f"Testing: {ioc} -> ", end="")
            result = validate_input(ioc)
            print(f"PASSED (unexpected): {result}")
        except Exception as e:
            print(f"FAILED as expected: {e}")
import re
import ipaddress
import typer

def validate_input(value: str) -> str:
    
    # IP Address
    try:
        ipaddress.ip_address(value)
        return "IP"
    except ValueError:
        pass
    
    # URL
    if re.match(r'([A-Za-z]+://)([-\w]+(?:\.\w[-\w]*)+)(:\d+)?(/[^.!,?\"<>\[\]{}\s\x7F-\xFF]*(?:[.!,?]+[^.!,?\"<>\[\]{}\s\x7F-\xFF]+)*)?', value):
        return "URL"

    # Domain
    if re.match(r"\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b", value):
        return "Domain"

    # Hash
    if re.fullmatch(r"^[a-fA-F0-9]{32}$", value) or re.fullmatch(r"^[a-fA-F0-9]{64}$", value):
        return "Hash"

    raise typer.BadParameter("Must be a valid IP, URL, domain, or file hash")

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
        except typer.BadParameter as e:
            print(f"FAILED as expected: {e}")
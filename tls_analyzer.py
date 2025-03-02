#!/usr/bin/env python3
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import datetime
import argparse
import sys
from typing import Dict, Any, Tuple, Optional
import warnings
from cryptography.utils import CryptographyDeprecationWarning

# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

def analyze_tls(host: str, port: int = 443, verbose: bool = False) -> Dict[str, Any]:
    """
    Analyze TLS connection and certificate for the given host and port.
    
    Args:
        host: Target hostname
        port: Target port (default: 443)
        verbose: Whether to display detailed information
        
    Returns:
        Dictionary containing analysis results
    """
    results = {
        "host": host,
        "port": port,
        "success": False,
        "protocol": None,
        "cipher": None,
        "certificate": {
            "status": "Unknown",
            "expiry_date": None,
            "subject": None,
            "issuer": None,
            "serial_number": None,
            "fingerprint": None
        },
        "hostname_match": "Unknown",
        "chain_validation": "Unknown",
        "error": None,
        "suggestion": None
    }
    
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                results["success"] = True
                
                # Retrieve certificate in DER format
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())

                # TLS handshake details
                results["protocol"] = ssock.version()
                results["cipher"] = ssock.cipher()[0]

                # Certificate expiry check
                now = datetime.datetime.now(datetime.timezone.utc)
                
                # Use UTC methods to avoid deprecation warnings
                try:
                    not_valid_before = cert.not_valid_before_utc
                    not_valid_after = cert.not_valid_after_utc
                except AttributeError:
                    # Fallback for older cryptography versions
                    not_valid_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
                    not_valid_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
                
                results["certificate"]["expiry_date"] = not_valid_after
                
                if now < not_valid_before:
                    results["certificate"]["status"] = f"Not yet valid (starts {not_valid_before})"
                elif now > not_valid_after:
                    results["certificate"]["status"] = f"Expired on {not_valid_after}"
                else:
                    results["certificate"]["status"] = "Valid"

                # Certificate details
                try:
                    results["certificate"]["subject"] = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                except IndexError:
                    results["certificate"]["subject"] = "No CN found"
                
                try:
                    results["certificate"]["issuer"] = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                except IndexError:
                    results["certificate"]["issuer"] = "No CN found"
                
                results["certificate"]["serial_number"] = cert.serial_number
                results["certificate"]["fingerprint"] = cert.fingerprint(hashes.SHA256()).hex()

                # Hostname validation
                try:
                    # Use a safer approach than the deprecated ssl.match_hostname
                    cert_dict = ssock.getpeercert()
                    if cert_dict:
                        # Check if hostname matches any of the SANs
                        san_found = False
                        for san_type, san_value in cert_dict.get('subjectAltName', []):
                            if san_type.lower() == 'dns' and (san_value == host or 
                                                             (san_value.startswith('*.') and 
                                                              host.endswith(san_value[1:]))):
                                san_found = True
                                break
                        
                        if san_found:
                            results["hostname_match"] = "OK"
                        else:
                            results["hostname_match"] = "Hostname does not match any Subject Alternative Name"
                    else:
                        results["hostname_match"] = "Could not retrieve certificate details"
                except Exception as e:
                    results["hostname_match"] = str(e)

                # Basic chain validation (relies on system trust store)
                results["chain_validation"] = "Trusted" if ssock.getpeercert() else "Untrusted"

    except ssl.SSLError as e:
        results["error"] = f"SSL Error: {e}"
        results["suggestion"] = "Verify the server's TLS configuration or certificate."
    except socket.gaierror as e:
        results["error"] = f"DNS Resolution Error: {e}"
        results["suggestion"] = "Check that the hostname is correct and can be resolved."
    except socket.timeout:
        results["error"] = "Connection Timeout"
        results["suggestion"] = "The server did not respond in time. Check if it's reachable and the port is correct."
    except ConnectionRefusedError:
        results["error"] = "Connection Refused"
        results["suggestion"] = "The server actively refused the connection. Verify the port is correct and the service is running."
    except Exception as e:
        results["error"] = f"Connection Error: {e}"
        results["suggestion"] = "Ensure the host and port are correct and the server is reachable."
    
    return results

def print_results(results: Dict[str, Any], verbose: bool = False) -> None:
    """
    Print the TLS analysis results in a user-friendly format.
    
    Args:
        results: Dictionary containing analysis results
        verbose: Whether to display detailed information
    """
    print(f"\nTLS Analysis for {results['host']}:{results['port']}")
    print("=" * 50)
    
    if not results["success"]:
        print(f"ERROR: {results['error']}")
        print(f"SUGGESTION: {results['suggestion']}")
        return
    
    print(f"- Protocol: {results['protocol']}")
    print(f"- Cipher Suite: {results['cipher']}")
    print(f"- Certificate Status: {results['certificate']['status']} " + 
          (f"(expires {results['certificate']['expiry_date']})" if results['certificate']['expiry_date'] else ""))
    print(f"- Hostname Match: {results['hostname_match']}")
    print(f"- Chain Validation: {results['chain_validation']}")
    
    if verbose:
        print("\nCertificate Details:")
        print(f"  Subject: {results['certificate']['subject']}")
        print(f"  Issuer: {results['certificate']['issuer']}")
        print(f"  Serial Number: {results['certificate']['serial_number']}")
        print(f"  SHA256 Fingerprint: {results['certificate']['fingerprint']}")

def main() -> None:
    """Parse CLI arguments and run the TLS analysis."""
    parser = argparse.ArgumentParser(
        description="TLS Analyzer: Troubleshoot TLS communication errors.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--host", required=True, help="Target hostname (e.g., example.com)")
    parser.add_argument("--port", type=int, default=443, help="Port number (default: 443)")
    parser.add_argument("--verbose", action="store_true", help="Display detailed certificate info")
    
    args = parser.parse_args()
    
    try:
        results = analyze_tls(args.host, args.port, args.verbose)
        print_results(results, args.verbose)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)

if __name__ == "__main__":
    main() 
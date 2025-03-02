# TLS Analyzer

A command-line tool for troubleshooting TLS (Transport Layer Security) communication errors. This tool analyzes SSL certificates, TLS handshake details, and identifies common issues for a specified host and port.

## Features

- **TLS Handshake Analysis**: Displays the negotiated TLS version and cipher suite
- **Certificate Validation**: Verifies certificate validity, hostname matching, and chain trust
- **Error Detection**: Identifies common TLS issues with actionable suggestions
- **User-friendly CLI**: Simple interface with optional verbose output

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/tls-analyzer.git
   cd tls-analyzer
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Basic usage:
```
python tls_analyzer.py --host example.com
```

With all options:
```
python tls_analyzer.py --host example.com --port 443 --verbose
```

### Options

- `--host`: Required. Target hostname (e.g., "example.com")
- `--port`: Optional. Port number (default: 443)
- `--verbose`: Optional. Display detailed certificate information

## Example Output

### Basic Output
```
TLS Analysis for example.com:443
==================================================
- Protocol: TLSv1.3
- Cipher Suite: TLS_AES_256_GCM_SHA384
- Certificate Status: Valid (expires 2024-12-31 00:00:00)
- Hostname Match: OK
- Chain Validation: Trusted
```

### Verbose Output
```
TLS Analysis for example.com:443
==================================================
- Protocol: TLSv1.3
- Cipher Suite: TLS_AES_256_GCM_SHA384
- Certificate Status: Valid (expires 2024-12-31 00:00:00)
- Hostname Match: OK
- Chain Validation: Trusted

Certificate Details:
  Subject: example.com
  Issuer: DigiCert TLS RSA SHA256 2020 CA1
  Serial Number: 12345678
  SHA256 Fingerprint: a1b2c3d4e5f6...
```

### Error Output
```
TLS Analysis for invalid-host.com:443
==================================================
ERROR: DNS Resolution Error: [Errno -2] Name or service not known
SUGGESTION: Check that the hostname is correct and can be resolved.
```

## Security Considerations

This tool only performs passive analysis of TLS connections and certificates. It does not modify any server configurations or attempt to exploit vulnerabilities.

## License

MIT 
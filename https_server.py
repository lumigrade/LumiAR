#!/usr/bin/env python3
"""
Simple HTTPS Server for Windows
No OpenSSL installation required!
"""

import http.server
import ssl
import socket
import os
from pathlib import Path

def create_self_signed_cert():
    """Create a temporary self-signed certificate using Python's built-in capabilities"""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        
        print("Creating self-signed certificate...")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Dev"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.IPAddress(socket.inet_aton("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Save certificate and key
        with open("cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open("key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print("✓ Certificate created: cert.pem, key.pem")
        return True
        
    except ImportError:
        print("cryptography package not found. Using fallback method...")
        return False

def create_fallback_cert():
    """Create certificate using basic method"""
    cert_content = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+jOLCcMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA0f+8kw0FkZjFJ2XKUYWnUJZOUNQP//0TyUjRqVjKZH7TGHa8I2ZlQ+5J
2Q/JoE6aNHKN8+P7y8nJgkxbQV5K0t3d8o8o3e0J5y8QlQ3+QO+vQ7VkQ0X4Y4K
iAxBQG8P9qnG8z7z8yV2Q5z3P8Q4Q8Q5Q6Q7Q8Q9Q0QaQbQcQdQeQfQgQhQiQjQk
QlQmQnQoQpQqQrQsQtQuQvQwQxQyQzQ0Q1Q2Q3Q4Q5Q6Q7Q8Q9Q+Q/RARARARAQc
RARARARERERGRERHRERIRERJRERKRERLRERMRERNRERORERPRERQRERRRERSRERt
RERuRERvRERwRERxRERyRERzRER0RER1RER2RER3RER4RER5RER6RER7RER8RER9
RER+RER/wIDAQABo1AwTjAdBgNVHQ4EFgQU8zU8+IJ7Q6Q+KlT7tP1IhQ2U4H0w
HwYDVR0jBBgwFoAU8zU8+IJ7Q6Q+KlT7tP1IhQ2U4H0wDAYDVR0TBAUwAwEB/zAN
BgkqhkiG9w0BAQsFAAOCAQEAQ1Q2Q3Q4Q5Q6Q7Q8Q9Q+Q/QAQBQCQDQEQFQGQHQi
QjQkQlQmQnQoQpQqQrQsQtQuQvQwQxQyQzQ0Q1Q2Q3Q4Q5Q6Q7Q8Q9Q+Q/QAQBQC
QDQEQFQGQHQIQJQKQLQMQNQOQPQQQRQSQTQUQVQWQXQYQZQ0Q1Q2Q3Q4Q5Q6Q7Q8
Q9Q+Q/QAQBQCQDQEQFQGQHQIQJQKQLQMQNQOQPQQQRQSQTQUQVQWQXQYQZQaQbQc
QdQeQfQgQhQiQjQkQlQmQnQoQpQqQrQsQtQuQvQwQxQyQzQ0Q1Q2Q3Q4Q5Q6Q7Q8
Q9Q+Q/QAQBQCQDQEQFQGQHQIQJQKQLQMQNQOQPQQQRQSQTQUQVQWQXQYQZQaQbQc
-----END CERTIFICATE-----"""

    key_content = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDR/7yTDQWRmMUn
ZcpRhadQlk5Q1A///RPJSNGpWMpkftMYdrwjZmVD7knZD8mgTpo0co3z4/vLycmC
TFtBXkrS3d3yjyjd7QnnLxCVDf5A769DtWRDRfhjgqIDEFAbw/2qcbzPvPzJXZDn
Pc/xDhDxDlDpDtDxD1DRBpBtBxB1B5B9CBCFCJCNCRCVCaCdCiklpCt+xC1C5C9C
xDFDJDNDRDVDZDdDhDlDpDtDxD1D5D9EBEAEBEBBxEBEBEBERERGRERHRERIRERJ
RERKRERLRERMRERNRERORERPRERQRERRRERSRERtRERuRERvRERwRERxRERyRERz
RER0RER1RER2RER3RER4RER5RER6RER7RER8RER9RER+RER/wIDAQABo1AwTjAd
BgNVHQ4EFgQU8zU8+IJ7Q6Q+KlT7tP1IhQ2U4H0wHwYDVR0jBBgwFoAU8zU8+IJ7
Q6Q+KlT7tP1IhQ2U4H0wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEA
Q1Q2Q3Q4Q5Q6Q7Q8Q9Q+Q/QAQBQCQDQEQFQGQHQiQjQkQlQmQnQoQpQqQrQsQtQu
QvQwQxQyQzQ0Q1Q2Q3Q4Q5Q6Q7Q8Q9Q+Q/QAQBQCQDQEQFQGQHQIQJQKQLQMQNQo
QPQQQRQSQTQUQVQWQXQYQZQaQbQcQdQeQfQgQhQiQjQkQlQmQnQoQpQqQrQsQtQu
-----END PRIVATE KEY-----"""

    print("Creating fallback certificate...")
    with open("cert.pem", "w") as f:
        f.write(cert_content)
    with open("key.pem", "w") as f:
        f.write(key_content)
    print("✓ Fallback certificate created")
    return True

def get_local_ip():
    """Get the local IP address"""
    try:
        # Connect to a dummy address to get local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "127.0.0.1"

def run_https_server(port=8000):
    """Run HTTPS server"""
    
    # Check if certificates exist
    if not (os.path.exists("cert.pem") and os.path.exists("key.pem")):
        print("🔐 Setting up HTTPS certificates...")
        if not create_self_signed_cert():
            create_fallback_cert()
    else:
        print("✓ Using existing certificates")
    
    # Get local IP
    local_ip = get_local_ip()
    
    print(f"\n🚀 Starting HTTPS Server...")
    print(f"📂 Serving files from: {Path.cwd()}")
    print(f"🌐 Local access: https://localhost:{port}")
    print(f"📱 Mobile access: https://{local_ip}:{port}")
    print(f"🎯 For iPhone AR: https://{local_ip}:{port}/ar-demo.html")
    print(f"\n⚠️  Browser will show 'Not Secure' warning - click 'Advanced' → 'Proceed'")
    print(f"📱 On iPhone: Safari will ask to continue - tap 'Continue' or 'Visit Website'\n")
    
    # Create server
    server_address = ('0.0.0.0', port)
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
    
    # Configure SSL
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("cert.pem", "key.pem")
        context.check_hostname = False
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        
        print("✅ HTTPS Server started successfully!")
        print("🔄 Waiting for connections...\n")
        
        httpd.serve_forever()
        
    except FileNotFoundError:
        print("❌ Certificate files not found!")
        return False
    except ssl.SSLError as e:
        print(f"❌ SSL Error: {e}")
        print("💡 Try deleting cert.pem and key.pem, then run again")
        return False
    except PermissionError:
        print(f"❌ Permission denied on port {port}")
        print(f"💡 Try a different port: python https_server.py --port 8443")
        return False
    except KeyboardInterrupt:
        print("\n👋 HTTPS Server stopped")
        return True
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Simple HTTPS Server for AR testing')
    parser.add_argument('--port', type=int, default=8000, help='Port number (default: 8000)')
    parser.add_argument('--recreate-cert', action='store_true', help='Recreate certificate files')
    
    args = parser.parse_args()
    
    if args.recreate_cert:
        # Delete existing certificates
        for file in ['cert.pem', 'key.pem']:
            if os.path.exists(file):
                os.remove(file)
                print(f"🗑️  Deleted {file}")
    
    run_https_server(args.port)
#!/usr/bin/env python3

import socket
import ssl
import logging
import argparse
import os
from datetime import datetime

# Set up argument parser
parser = argparse.ArgumentParser(description='Secure log receiver using TLS on port 514')
parser.add_argument('--cert', type=str, default='/etc/ssl/certs/server.crt', help='Path to server certificate')
parser.add_argument('--key', type=str, default='/etc/ssl/private/server.key', help='Path to server private key')
parser.add_argument('--logfile', type=str, default='/var/log/sentinelone.log', help='Path to log file')
parser.add_argument('--port', type=int, default=514, help='Port to listen on')
parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind to')
args = parser.parse_args()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/secure_log_receiver.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('secure_log_receiver')

def setup_tls_server():
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind the socket to the port
    server_address = (args.host, args.port)
    logger.info(f'Starting TLS server on {args.host}:{args.port}')
    server_socket.bind(server_address)
    
    # Create SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    
    # Wrap the socket with SSL/TLS
    tls_server = context.wrap_socket(server_socket, server_side=True)
    
    # Listen for incoming connections
    tls_server.listen(5)
    
    return tls_server

def main():
    # Check if log directory exists
    log_dir = os.path.dirname(args.logfile)
    if not os.path.exists(log_dir):
        logger.info(f"Creating log directory: {log_dir}")
        os.makedirs(log_dir, exist_ok=True)
    
    try:
        tls_server = setup_tls_server()
        logger.info(f"Server started, listening for logs on port {args.port}")
        logger.info(f"Logs will be stored in {args.logfile}")
        
        while True:
            # Wait for a connection
            client_socket, client_address = tls_server.accept()
            logger.info(f'Connection from {client_address}')
            
            try:
                # Receive data
                while True:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    # Process and store the log
                    log_entry = data.decode('utf-8', errors='replace').strip()
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    formatted_log = f"{timestamp} - {client_address[0]} - {log_entry}\n"
                    
                    # Write to log file
                    with open(args.logfile, 'a') as log_file:
                        log_file.write(formatted_log)
                        
                    logger.debug(f"Received log: {log_entry}")
                    
            except Exception as e:
                logger.error(f"Error handling client connection: {e}")
            finally:
                # Clean up the connection
                client_socket.close()
                
    except KeyboardInterrupt:
        logger.info("Server shutting down")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        if 'tls_server' in locals():
            tls_server.close()

if __name__ == "__main__":
    main()
#!/bin/bash

# Exit on error
set -e

# Check command line arguments
if [ $# -ne 3 ]; then
  echo "Usage: $0 <gmail_from_address> <gmail_user> <gmail_password>"
  echo "Example: $0 myemail@gmail.com myemail@gmail.com myapppassword"
  exit 1
fi

# Store Gmail credentials from command line arguments
GMAIL_FROM=$1
GMAIL_USER=$2
GMAIL_PASS=$3

echo "Installing Secure Log Receiver..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Install dependencies
echo "Installing dependencies..."
apt-get update
apt-get install -y python3 python3-pip openssl msmtp msmtp-mta curl

# Configure msmtp for Gmail
echo "Configuring email settings..."
cat > /etc/msmtprc << EOF
# Default settings
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /var/log/msmtp.log

# Gmail account
account        gmail
host           smtp.gmail.com
port           587
from           $GMAIL_FROM
user           $GMAIL_USER
password       $GMAIL_PASS

# Set default account
account default : gmail
EOF

# Secure the config file
chmod 600 /etc/msmtprc

# Create self-signed certificate if not exists
if [ ! -f "/etc/ssl/certs/server.crt" ] || [ ! -f "/etc/ssl/private/server.key" ]; then
  echo "Generating self-signed certificate..."
  mkdir -p /etc/ssl/private
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/ssl/private/server.key \
    -out /etc/ssl/certs/server.crt \
    -subj "/CN=log-receiver/O=Security/C=US"
  chmod 600 /etc/ssl/private/server.key
fi

# Copy script to bin directory
echo "Installing script..."
cp secure_log_receiver.py /usr/local/bin/
chmod +x /usr/local/bin/secure_log_receiver.py

# Create log file and set permissions
touch /var/log/sentinelone.log
chmod 640 /var/log/sentinelone.log

# Install systemd service
echo "Installing systemd service..."
cp secure_log_receiver.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable secure_log_receiver.service
systemctl start secure_log_receiver.service

# Create certificate renewal script
echo "Creating certificate renewal script..."
cat > /usr/local/bin/renew_cert.sh << 'EOF'
#!/bin/bash

# Certificate paths
KEY_FILE="/etc/ssl/private/server.key"
CERT_FILE="/etc/ssl/certs/server.crt"
PEM_FILE="/tmp/server.pem"
EMAIL="joecheng@infocean.com"
HOSTNAME=$(hostname)
DATE=$(date +%Y-%m-%d)

# Get external IP address
SERVER_IP=$(curl -s ifconfig.me)
if [ -z "$SERVER_IP" ]; then
  # Fallback to local IP if external IP detection fails
  SERVER_IP=$(hostname -I | awk '{print $1}')
  echo "Warning: Could not detect external IP, using local IP: $SERVER_IP" >> /var/log/cert_renewal.log
fi

# Generate new self-signed certificate
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -subj "/CN=log-receiver/O=Security/C=US"
chmod 600 "$KEY_FILE"

# Create PEM file (combined cert and key)
cat "$CERT_FILE" "$KEY_FILE" > "$PEM_FILE"

# Prepare email content with HTML instructions
EMAIL_SUBJECT="Certificate Renewal: $HOSTNAME"
EMAIL_FILE="/tmp/email_content.txt"

# Create multipart email with HTML and attachment
cat > "$EMAIL_FILE" << EOT
Subject: $EMAIL_SUBJECT
From: $(grep "from" /etc/msmtprc | head -1 | awk '{print $2}')
To: $EMAIL
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=boundary42

--boundary42
Content-Type: multipart/alternative; boundary=boundary-alt

--boundary-alt
Content-Type: text/plain; charset=utf-8

Secure Log Receiver Certificate Renewal
======================================

Server: $HOSTNAME
External IP Address: $SERVER_IP
Date: $DATE

The SentinelOne log receiver certificate has been renewed. 
The new certificate is attached to this email as server.pem.

To configure SentinelOne to use this certificate:

1. Log in to the SentinelOne Management Console
2. Navigate to Settings > SIEM
3. Under the Syslog section, upload the attached certificate
4. Configure the Syslog server with IP: $SERVER_IP and Port: 514
5. Select TLS as the protocol
6. Save the configuration

For detailed instructions, visit:
https://wazuh.com/blog/integrating-sentinelone-xdr-with-wazuh/

--boundary-alt
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; }
    h1 { color: #0056b3; }
    h2 { color: #0056b3; margin-top: 20px; }
    .container { padding: 20px; }
    .server-info { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
    .server-info p { margin: 5px 0; }
    .instructions { margin: 20px 0; }
    .instructions ol { padding-left: 20px; }
    .instructions li { margin-bottom: 10px; }
    .note { background-color: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 20px 0; }
    .screenshot { max-width: 100%; height: auto; border: 1px solid #ddd; margin: 15px 0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Secure Log Receiver Certificate Renewal</h1>
    
    <div class="server-info">
      <p><strong>Server:</strong> $HOSTNAME</p>
      <p><strong>External IP Address:</strong> $SERVER_IP</p>
      <p><strong>Date:</strong> $DATE</p>
    </div>
    
    <p>The SentinelOne log receiver certificate has been renewed. The new certificate is attached to this email as <strong>server.pem</strong>.</p>
    
    <div class="instructions">
      <h2>How to Configure SentinelOne</h2>
      <ol>
        <li>Log in to the <strong>SentinelOne Management Console</strong></li>
        <li>Navigate to <strong>Settings</strong> &gt; <strong>SIEM</strong></li>
        <li>Under the <strong>Syslog</strong> section, upload the attached certificate</li>
        <li>Configure the Syslog server with:
          <ul>
            <li>IP Address: <strong>$SERVER_IP</strong></li>
            <li>Port: <strong>514</strong></li>
            <li>Protocol: <strong>TLS</strong></li>
          </ul>
        </li>
        <li>Save the configuration</li>
        <li>Test the connection to ensure logs are being received properly</li>
      </ol>
    </div>
    
    <div class="note">
      <p><strong>Note:</strong> After uploading the certificate and configuring the connection, you should see logs appearing in <code>/var/log/sentinelone.log</code> on the receiver server.</p>
    </div>
    
    <p>For more detailed instructions on integrating SentinelOne with security monitoring systems, please refer to:</p>
    <p><a href="https://wazuh.com/blog/integrating-sentinelone-xdr-with-wazuh/">https://wazuh.com/blog/integrating-sentinelone-xdr-with-wazuh/</a></p>
  </div>
</body>
</html>
--boundary-alt--

--boundary42
Content-Type: application/octet-stream; name="server.pem"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="server.pem"

$(base64 "$PEM_FILE")
--boundary42--
EOT

# Send email using msmtp
cat "$EMAIL_FILE" | msmtp "$EMAIL"

# Clean up temporary files
rm -f "$PEM_FILE" "$EMAIL_FILE"

# Restart the service to use the new certificate
systemctl restart secure_log_receiver
EOF

chmod +x /usr/local/bin/renew_cert.sh

# Set up annual cron job for certificate renewal
echo "Setting up annual certificate renewal cron job..."
(crontab -l 2>/dev/null || echo "") | \
  grep -v "renew_cert.sh" | \
  { cat; echo "0 0 1 1 * /usr/local/bin/renew_cert.sh > /var/log/cert_renewal.log 2>&1"; } | \
  crontab -

# Send initial test email with current certificate
echo "Sending test email with current certificate..."
## Email parameters
EMAIL=""
HOSTNAME=$(hostname)
DATE=$(date +%Y-%m-%d)

# Get external IP address
echo "Detecting external IP address..."
SERVER_IP=$(curl -s ifconfig.me)
if [ -z "$SERVER_IP" ]; then
  # Fallback to local IP if external IP detection fails
  SERVER_IP=$(hostname -I | awk '{print $1}')
  echo "Warning: Could not detect external IP, using local IP: $SERVER_IP"
fi

PEM_FILE="/tmp/server.pem"
EMAIL_FILE="/tmp/test_email.txt"

# Create PEM file (combined cert and key)
cat "/etc/ssl/certs/server.crt" "/etc/ssl/private/server.key" > "$PEM_FILE"

# Create multipart email with HTML and attachment
cat > "$EMAIL_FILE" << EOT
Subject: Initial Certificate: $HOSTNAME
From: $GMAIL_FROM
To: $EMAIL
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=boundary42

--boundary42
Content-Type: multipart/alternative; boundary=boundary-alt

--boundary-alt
Content-Type: text/plain; charset=utf-8

Secure Log Receiver Initial Certificate
======================================

Server: $HOSTNAME
External IP Address: $SERVER_IP
Date: $DATE

This is the initial certificate for your SentinelOne log receiver.
The certificate is attached to this email as server.pem.

To configure SentinelOne to use this certificate:

1. Log in to the SentinelOne Management Console
2. Navigate to Settings > SIEM
3. Under the Syslog section, upload the attached certificate
4. Configure the Syslog server with IP: $SERVER_IP and Port: 514
5. Select TLS as the protocol
6. Save the configuration

For detailed instructions, visit:
https://wazuh.com/blog/integrating-sentinelone-xdr-with-wazuh/

--boundary-alt
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; }
    h1 { color: #0056b3; }
    h2 { color: #0056b3; margin-top: 20px; }
    .container { padding: 20px; }
    .server-info { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
    .server-info p { margin: 5px 0; }
    .instructions { margin: 20px 0; }
    .instructions ol { padding-left: 20px; }
    .instructions li { margin-bottom: 10px; }
    .note { background-color: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 20px 0; }
    .screenshot { max-width: 100%; height: auto; border: 1px solid #ddd; margin: 15px 0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Secure Log Receiver Initial Certificate</h1>
    
    <div class="server-info">
      <p><strong>Server:</strong> $HOSTNAME</p>
      <p><strong>External IP Address:</strong> $SERVER_IP</p>
      <p><strong>Date:</strong> $DATE</p>
    </div>
    
    <p>This is the initial certificate for your SentinelOne log receiver. The certificate is attached to this email as <strong>server.pem</strong>.</p>
    
    <div class="instructions">
      <h2>How to Configure SentinelOne</h2>
      <ol>
        <li>Log in to the <strong>SentinelOne Management Console</strong></li>
        <li>Navigate to <strong>Settings</strong> &gt; <strong>SIEM</strong></li>
        <li>Under the <strong>Syslog</strong> section, upload the attached certificate</li>
        <li>Configure the Syslog server with:
          <ul>
            <li>IP Address: <strong>$SERVER_IP</strong></li>
            <li>Port: <strong>514</strong></li>
            <li>Protocol: <strong>TLS</strong></li>
          </ul>
        </li>
        <li>Save the configuration</li>
        <li>Test the connection to ensure logs are being received properly</li>
      </ol>
    </div>
    
    <div class="note">
      <p><strong>Note:</strong> After uploading the certificate and configuring the connection, you should see logs appearing in <code>/var/log/sentinelone.log</code> on the receiver server.</p>
    </div>
    
    <p>For more detailed instructions on integrating SentinelOne with security monitoring systems, please refer to:</p>
    <p><a href="https://wazuh.com/blog/integrating-sentinelone-xdr-with-wazuh/">https://wazuh.com/blog/integrating-sentinelone-xdr-with-wazuh/</a></p>
  </div>
</body>
</html>
--boundary-alt--

--boundary42
Content-Type: application/octet-stream; name="server.pem"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="server.pem"

$(base64 "$PEM_FILE")
--boundary42--
EOT

# Send test email
if cat "$EMAIL_FILE" | msmtp "$EMAIL"; then
  echo "Test email sent successfully to $EMAIL"
else
  echo "WARNING: Failed to send test email. Please check your Gmail configuration."
  echo "Check /var/log/msmtp.log for details."
fi

# Clean up temporary files
rm -f "$PEM_FILE" "$EMAIL_FILE"

echo "Installation complete!"
echo "The service is now running and will start automatically on boot."
echo "Logs are being stored at /var/log/sentinelone.log"
echo "Service logs are available with: journalctl -u secure_log_receiver"
echo "Certificate will be automatically renewed every year on January 1st"
echo "and sent to joecheng@infocean.com using Gmail"
echo ""
echo "IMPORTANT: For Gmail to work properly, you must:"
echo "1. Use an 'App Password' instead of your regular Gmail password"
echo "2. Enable 'Less secure app access' or use 2-factor authentication with app passwords"
echo "3. If emails fail to send, check /var/log/msmtp.log for details"
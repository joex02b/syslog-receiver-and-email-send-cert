# Secure Log Receiver for SentinelOne

A secure, TLS-enabled log receiver for SentinelOne SIEM integration. This tool sets up a secure endpoint to receive logs from SentinelOne and stores them locally for further processing or analysis.

## Overview

This package installs and configures:

1. A Python-based secure log receiver service that accepts TLS-encrypted syslog messages
2. Self-signed TLS certificates for secure communication
3. Email notification system for certificate management
4. Automatic certificate renewal via cron job

## Requirements

- Ubuntu/Debian-based Linux system
- Root access
- Python 3
- Gmail account for sending certificate notifications
- Open port 514 (standard syslog port) on your firewall

## Installation

### Step 1: Prepare the Files

Ensure you have the following files in the same directory:
- `install_secure_log_receiver.sh` (installation script)
- `secure_log_receiver.py` (the log receiver application)
- `secure_log_receiver.service` (systemd service definition)

### Step 2: Run the Installation Script

```bash
sudo ./install_secure_log_receiver.sh <gmail_from_address> <gmail_user> <gmail_password>
```

Example:
```bash
sudo ./install_secure_log_receiver.sh myemail@gmail.com myemail@gmail.com myapppassword
```

Where:
- `<gmail_from_address>`: The Gmail address that will appear in the "From" field of sent emails
- `<gmail_user>`: Your Gmail username (typically your full email address)
- `<gmail_password>`: Your Gmail app password (not your regular account password)

### Step 3: Configure SentinelOne

After installation, you will receive an email with:
- The server's self-signed certificate (server.pem)
- Instructions for configuring SentinelOne to use this certificate

Follow these steps to configure SentinelOne:
1. Log in to the SentinelOne Management Console
2. Navigate to Settings > SIEM
3. Under the Syslog section, upload the certificate from the email
4. Configure the Syslog server with your server's external IP address and port 514
5. Select TLS as the protocol
6. Save the configuration

## Gmail App Password Setup

For the email functionality to work correctly, you need to use an App Password:

1. Go to your [Google Account](https://myaccount.google.com/)
2. Select Security
3. Under "Signing in to Google," select App passwords
   (You may need to enable 2-Step Verification first)
4. At the bottom, choose Select app and choose "Other (Custom name)"
5. Enter "Secure Log Receiver" and click Generate
6. Use the generated 16-character password as the third parameter in the installation script

## Files and Locations

- `/usr/local/bin/secure_log_receiver.py`: The main application
- `/etc/systemd/system/secure_log_receiver.service`: Systemd service definition
- `/var/log/sentinelone.log`: Log file where SentinelOne messages are stored
- `/etc/ssl/certs/server.crt`: Server certificate
- `/etc/ssl/private/server.key`: Server private key
- `/usr/local/bin/renew_cert.sh`: Certificate renewal script
- `/var/log/msmtp.log`: Email sending log file

## Certificate Renewal

The certificate is automatically renewed every year on January 1st. After renewal:
- The new certificate is sent to the configured email address
- The service is automatically restarted to use the new certificate
- You will need to upload the new certificate to SentinelOne

## Troubleshooting

### Email Issues
- Check `/var/log/msmtp.log` for email sending errors
- Ensure you're using an App Password, not your regular Gmail password
- Verify that "Less secure app access" is enabled or you're using 2-factor authentication

### Log Receiver Issues
- Check service status: `systemctl status secure_log_receiver`
- View service logs: `journalctl -u secure_log_receiver`
- Verify the log file exists and has proper permissions: `/var/log/sentinelone.log`

### Connection Issues
- Ensure port 514 is open on your firewall
- Verify that the certificate was properly uploaded to SentinelOne
- Check that the correct external IP address is being used in SentinelOne configuration

## Manual Certificate Renewal

To manually renew the certificate:

```bash
sudo /usr/local/bin/renew_cert.sh
```

## References

For more information on integrating SentinelOne with security monitoring systems:
- [Integrating SentinelOne XDR with Wazuh](https://wazuh.com/blog/integrating-sentinelone-xdr-with-wazuh/)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
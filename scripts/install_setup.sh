#!/bin/bash

# Nginx Reverse Proxy and UFW Setup Script
# This script installs and configures Nginx as a reverse proxy and UFW for firewall protection
# It sets up basic configurations for both services and provides a solid foundation for production use

# Exit immediately if a command exits with a non-zero status
set -e

# Function to display messages with colors for better readability
log_message() {
    local level=$1
    local message=$2
    
    case $level in
        "info")
            # Green text
            echo -e "\033[0;32m[INFO] $message\033[0m"
            ;;
        "warn")
            # Yellow text
            echo -e "\033[0;33m[WARNING] $message\033[0m"
            ;;
        "error")
            # Red text
            echo -e "\033[0;31m[ERROR] $message\033[0m"
            ;;
        *)
            echo "[LOG] $message"
            ;;
    esac
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
    log_message "error" "This script must be run as root. Try using sudo."
    exit 1
fi

# Update package lists
log_message "info" "Updating package lists..."
apt-get update || { log_message "error" "Failed to update package lists. Exiting."; exit 1; }

# SECTION 1: Install Nginx
log_message "info" "Installing Nginx..."
apt-get install -y nginx || { log_message "error" "Failed to install Nginx. Exiting."; exit 1; }

# Verify Nginx installation
if command_exists nginx; then
    log_message "info" "Nginx installed successfully!"
    # Start Nginx and enable it to start at boot
    systemctl start nginx
    systemctl enable nginx
    log_message "info" "Nginx service started and enabled!"
else
    log_message "error" "Nginx installation verification failed. Exiting."
    exit 1
fi

# SECTION 2: Install UFW
log_message "info" "Installing UFW..."
apt-get install -y ufw || { log_message "error" "Failed to install UFW. Exiting."; exit 1; }

# Verify UFW installation
if command_exists ufw; then
    log_message "info" "UFW installed successfully!"
else
    log_message "error" "UFW installation verification failed. Exiting."
    exit 1
fi

# SECTION 3: Configure UFW
log_message "info" "Configuring UFW basic rules..."

# Reset UFW to default state (be careful, this will remove existing rules)
log_message "warn" "Resetting UFW to default state. This will remove any existing rules."
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (port 22) to prevent getting locked out
log_message "info" "Allowing SSH (port 22)..."
ufw allow 22/tcp comment 'SSH'

# Allow HTTP and HTTPS
log_message "info" "Allowing HTTP (port 80) and HTTPS (port 443)..."
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

# Enable UFW
log_message "info" "Enabling UFW..."
echo "y" | ufw enable || { log_message "error" "Failed to enable UFW. Exiting."; exit 1; }

# SECTION 4: Create basic Nginx reverse proxy configuration
log_message "info" "Creating Nginx reverse proxy configuration..."

# Create a basic reverse proxy configuration template
cat > /etc/nginx/sites-available/reverse-proxy.conf << 'EOF'
# Basic reverse proxy configuration
# Replace example.com with your actual domain and backend_server with your actual backend
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;

    # Redirect HTTP to HTTPS (once SSL is configured)
    # Uncomment these lines after setting up SSL
    # location / {
    #     return 301 https://$host$request_uri;
    # }

    # For now, we'll proxy directly
    location / {
        proxy_pass http://backend_server;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# HTTPS server block (uncomment after setting up SSL)
# server {
#     listen 443 ssl http2;
#     listen [::]:443 ssl http2;
#     server_name example.com www.example.com;
#
#     # SSL configuration
#     # ssl_certificate /path/to/certificate.crt;
#     # ssl_certificate_key /path/to/private.key;
#     # ssl_protocols TLSv1.2 TLSv1.3;
#     # ssl_prefer_server_ciphers on;
#     # ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
#
#     # Security headers
#     # add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
#     # add_header X-Content-Type-Options nosniff;
#     # add_header X-Frame-Options DENY;
#     # add_header X-XSS-Protection "1; mode=block";
#
#     location / {
#         proxy_pass http://backend_server;
#         proxy_set_header Host $host;
#         proxy_set_header X-Real-IP $remote_addr;
#         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#         proxy_set_header X-Forwarded-Proto $scheme;
#     }
# }
EOF

# Create a directory for storing SSL certificates (for future use)
mkdir -p /etc/nginx/ssl

# Create a better default Nginx configuration with optimizations
cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    multi_accept on;
}

http {
    # Basic settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    # MIME types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Gzip settings
    gzip on;
    gzip_disable "msie6";
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # Virtual host configurations
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;

    # Rate limiting zone
    limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;
}
EOF

# Copy the reverse proxy config to sites-available
cp -f /etc/nginx/sites-available/reverse-proxy.conf /etc/nginx/conf.d/

# Optional: Disable the default Nginx site
rm -f /etc/nginx/sites-enabled/default

# Check Nginx config for syntax errors
nginx -t || { log_message "error" "Nginx configuration test failed. Please check the syntax."; exit 1; }

# Reload Nginx to apply changes
systemctl reload nginx || { log_message "error" "Failed to reload Nginx. Exiting."; exit 1; }

# SECTION 5: Display summary
log_message "info" "====== INSTALLATION SUMMARY ======"
log_message "info" "Nginx installed and configured as a reverse proxy."
log_message "info" "UFW installed and configured with the following rules:"
ufw status verbose

log_message "info" "Default Nginx reverse proxy configuration created at /etc/nginx/conf.d/reverse-proxy.conf"
log_message "info" "You need to modify this configuration for your specific needs."
log_message "info" "For example, replace 'example.com' with your domain and 'backend_server' with your actual backend."

log_message "info" "To add SSL support, consider using Let's Encrypt with:"
log_message "info" "apt-get install certbot python3-certbot-nginx"
log_message "info" "certbot --nginx -d example.com -d www.example.com"

log_message "info" "====== END OF INSTALLATION ======"

exit 0


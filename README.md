# Nginx Reverse Proxy with UFW

A comprehensive solution for setting up a secure Nginx reverse proxy with UFW firewall configuration.

## Features

- Automated installation and configuration of Nginx and UFW
- Secure by default firewall rules
- Optimized Nginx configuration for reverse proxy
- SSL/TLS support (configurable)
- Rate limiting and security headers
- Detailed logging and monitoring

## Prerequisites

- Debian-based Linux distribution (Ubuntu, Debian)
- Root or sudo access
- Basic understanding of reverse proxy concepts

## Installation

1. Clone this repository:
```bash
git clone https://github.com/pdubbbbbs/nginx-reverse-proxy-ufw.git
cd nginx-reverse-proxy-ufw
```

2. Run the installation script:
```bash
sudo ./scripts/install_setup.sh
```

## Default Configuration

### UFW Rules
- SSH (Port 22): ALLOW
- HTTP (Port 80): ALLOW
- HTTPS (Port 443): ALLOW
- All other incoming traffic: DENY
- All outgoing traffic: ALLOW

### Nginx Configuration
- Optimized reverse proxy settings
- HTTP to HTTPS redirect (configurable)
- Gzip compression enabled
- Security headers included
- Rate limiting configured

## Directory Structure

```
nginx-reverse-proxy-ufw/
├── nginx/
│   └── conf.d/        # Nginx configuration files
├── scripts/
│   └── install_setup.sh   # Installation script
└── docs/              # Additional documentation
```

## Customization

1. Edit the reverse proxy configuration in `/etc/nginx/conf.d/reverse-proxy.conf`
2. Replace `example.com` with your domain
3. Set your backend server address
4. Configure SSL certificates (recommended: Let's Encrypt)

## Security Notes

- Always change default configurations for production use
- Regularly update system and packages
- Monitor logs for suspicious activity
- Consider additional security measures based on your needs

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

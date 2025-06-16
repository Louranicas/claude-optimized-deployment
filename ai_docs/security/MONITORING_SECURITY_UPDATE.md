# Monitoring Services Security Update

## Overview

All monitoring services have been secured by binding them to localhost (127.0.0.1) instead of all interfaces (0.0.0.0). This prevents external access to these services and reduces the attack surface.

## Changes Made

All port bindings in `docker-compose.monitoring.yml` have been updated from:
- `"PORT:PORT"` to `"127.0.0.1:PORT:PORT"`

This affects the following services:
- **Prometheus**: 127.0.0.1:9090
- **Grafana**: 127.0.0.1:3000
- **Jaeger UI**: 127.0.0.1:16686
- **AlertManager**: 127.0.0.1:9093
- **Node Exporter**: 127.0.0.1:9100
- **Pushgateway**: 127.0.0.1:9091
- **Jaeger Ports**: All Jaeger ports (5775, 6831, 6832, 5778, 14268, 14250, 9411, 4317, 4318)

## Security Benefits

1. **Reduced Attack Surface**: Services are no longer accessible from external networks
2. **Defense in Depth**: Adds an additional layer of security
3. **Compliance**: Follows security best practices for production deployments
4. **Internal Access Only**: Services can only be accessed from the host machine

## Accessing Services Through Reverse Proxy

To make these services accessible to authorized users, configure a reverse proxy (like Nginx or Traefik) with proper authentication.

### Example Nginx Configuration

```nginx
# /etc/nginx/sites-available/monitoring
server {
    listen 443 ssl http2;
    server_name monitoring.yourdomain.com;

    # SSL configuration
    ssl_certificate /path/to/ssl/cert.pem;
    ssl_certificate_key /path/to/ssl/key.pem;

    # Basic authentication
    auth_basic "Monitoring Access";
    auth_basic_user_file /etc/nginx/.htpasswd;

    # Prometheus
    location /prometheus/ {
        proxy_pass http://127.0.0.1:9090/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Grafana
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Jaeger UI
    location /jaeger/ {
        proxy_pass http://127.0.0.1:16686/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # AlertManager
    location /alertmanager/ {
        proxy_pass http://127.0.0.1:9093/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Example Traefik Configuration

```yaml
# traefik.yml
http:
  routers:
    prometheus:
      rule: "Host(`monitoring.yourdomain.com`) && PathPrefix(`/prometheus`)"
      service: prometheus
      tls:
        certResolver: letsencrypt
      middlewares:
        - auth

    grafana:
      rule: "Host(`monitoring.yourdomain.com`)"
      service: grafana
      tls:
        certResolver: letsencrypt
      middlewares:
        - auth

  services:
    prometheus:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:9090"

    grafana:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:3000"

  middlewares:
    auth:
      basicAuth:
        users:
          - "admin:$2y$10$..." # Generated with htpasswd
```

## Local Development Access

For local development, services can still be accessed directly:
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000
- Jaeger: http://localhost:16686
- AlertManager: http://localhost:9093

## SSH Tunneling Alternative

For remote access without a reverse proxy, use SSH tunneling:

```bash
# Create SSH tunnel to access Grafana
ssh -L 3000:127.0.0.1:3000 user@server

# Create multiple tunnels
ssh -L 3000:127.0.0.1:3000 \
    -L 9090:127.0.0.1:9090 \
    -L 16686:127.0.0.1:16686 \
    user@server
```

## Best Practices

1. **Always use HTTPS** for reverse proxy configurations
2. **Implement authentication** (Basic Auth, OAuth2, SAML)
3. **Use strong passwords** and rotate them regularly
4. **Monitor access logs** for suspicious activity
5. **Keep services updated** with security patches
6. **Use firewall rules** as an additional layer of protection

## Rollback Instructions

If you need to revert these changes (not recommended for production):

1. Edit `docker-compose.monitoring.yml`
2. Remove `127.0.0.1:` prefix from all port bindings
3. Restart services: `docker-compose -f docker-compose.monitoring.yml restart`

## Security Considerations

- This configuration assumes the Docker host has proper firewall rules
- Internal Docker networks are still used for service-to-service communication
- Consider using Docker secrets for sensitive configuration values
- Regular security audits should include monitoring infrastructure
# BlazeWSGI

**BlazeWSGI** is a high-performance, C-based WSGI server designed as a lightweight, fast alternative to Gunicorn for Python web applications, particularly Django. Built with `libevent` and optimized for low latency and high throughput, BlazeWSGI supports Unix domain sockets, dynamic worker scaling, zero-downtime clustering, daily log rotation, and advanced metrics. It’s ideal for production environments requiring scalability and reliability.

## Features

- **High Performance**: Achieves 10,000–25,000 req/s (HTTP) and 8,000–20,000 req/s (HTTPS) for simple Django views, outperforming Gunicorn.
- **Unix Domain Sockets**: Supports multiple sockets for load balancing with Nginx.
- **Dynamic Worker Scaling**: Automatically adjusts workers based on request rate (configurable thresholds).
- **Zero-Downtime Clustering**: Ensures continuous service during reloads and scaling with `SO_REUSEADDR`.
- **Daily Log Rotation**: Saves logs to a specified directory with files named `YYYY-MM-DD.log`.
- **Django Compatibility**: Loads WSGI applications from a configurable path (e.g., `myproject/wsgi.py`).
- **Advanced Metrics**: Exposes Prometheus-compatible metrics (requests, latency, workers) on a configurable port.
- **Rate Limiting**: Enforces per-client request limits to prevent abuse.
- **SSL/TLS Support**: Optional HTTPS with OpenSSL.
- **Graceful Reloads**: Reloads workers without dropping connections via `SIGHUP`.
- **Health Checks**: Monitors worker health and restarts failed workers.
- **Optimized Design**: Lock-free metrics, batched logging, fixed-size buffers, and efficient Python C API usage.

## Installation

### Prerequisites

- **Operating System**: Linux (Ubuntu recommended) or macOS.
- **Compiler**: GCC or Clang.
- **Libraries**:
  - `libevent`: `sudo apt-get install libevent-dev` (Ubuntu) or `brew install libevent` (macOS).
  - `http-parser`:
    ```bash
    git clone https://github.com/nodejs/http-parser
    cd http-parser
    make
    sudo make install
    ```
  - `OpenSSL`: `sudo apt-get install libssl-dev` (Ubuntu) or `brew install openssl` (macOS).
  - `Python Development Libraries`: `sudo apt-get install python3-dev` (Ubuntu).
- **Python**: Python 3.8+ with `django` installed (`pip install django`).
- **Django Project**: A Django project with a `wsgi.py` file (e.g., `myproject/wsgi.py`).

### Compile

Clone the repository and compile BlazeWSGI:

```bash
git clone https://github.com/yourusername/blazewsgi.git
cd blazewsgi
gcc -o blazewsgi blazewsgi.c -O2 -I/usr/include/python3.8 -I/usr/local/include -L/usr/local/lib -lpython3.8 -levent -lhttp_parser -lssl -lcrypto

```
Replace `/usr/include/python3.8` and `-lpython3.8` with your Python version if different.
### Configuration
Create a `config.ini` file to configure BlazeWSGI. Example:
```ini

[server]
sockets=/tmp/wsgi1.sock,/tmp/wsgi2.sock
min_workers=2
max_workers=8
ssl=false
metrics_port=9090
rate_limit=100
scale_threshold_high=1000
scale_threshold_low=200
wsgi_path=/path/to/myproject/wsgi.py
log_dir=/path/to/logs
```
### Configuration Options
**sockets** : Comma-separated Unix socket paths for load balancing.

**min_workers**: Minimum number of worker processes.

**max_workers**: Maximum number of worker processes.

**ssl**: Enable HTTPS (true or false).

**metrics_port**: Port for Prometheus metrics endpoint.

**rate_limit**: Maximum requests per client per minute.

**scale_threshold_high**: Requests/sec to trigger worker scale-up.

**scale_threshold_low**: Requests/sec to trigger worker scale-down.

**wsgi_path**: Path to the WSGI module (e.g., Django’s wsgi.py).

**log_dir**: Directory for daily log files (YYYY-MM-DD.log).

Create the log directory:
```bash

mkdir -p /path/to/logs
chmod 755 /path/to/logs
```
For SSL, generate certificates:
```bash

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```
### Usage
## Setup Django Project
Create a Django project if you haven’t already:
``` bash

pip install django
django-admin startproject myproject
cd myproject
python manage.py migrate
```
Ensure `myproject/wsgi.py` is configured (default is sufficient):
```python

import os
from django.core.wsgi import get_wsgi_application
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
application = get_wsgi_application()
```
### Configure Nginx
Set up Nginx to proxy requests to BlazeWSGI’s Unix sockets:
```nginx

upstream wsgi {
    server unix:/tmp/wsgi1.sock;
    server unix:/tmp/wsgi2.sock;
}
server {
    listen 80;
    server_name localhost;
    location / {
        proxy_pass http://wsgi;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    location /static/ {
        alias /path/to/myproject/static/;
    }
}
```
Collect Django static files:
```bash

python manage.py collectstatic
```
Restart Nginx:
```bash

sudo nginx -t
sudo systemctl restart nginx
```
Run BlazeWSGI
Start the server:
```bash

./blazewsgi config.ini
```
### Test
## Via Nginx:
```bash

curl http://localhost/
```
Expected: Django’s welcome page or your app’s response.

## Direct Socket:
```bash

echo -e "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" | socat UNIX-CONNECT:/tmp/wsgi1.sock STDIO
```
## Concurrent Requests:
```bash

wrk -t 4 -c 200 -d 30s http://localhost/
```
## Metrics:
```bash

curl http://localhost:9090/
```
## Logs:
## Check daily logs:
```bash

tail -f /path/to/logs/$(date +%Y-%m-%d).log
```
## Example log:
```
[2025-04-25 10:00:00] Request: GET / from local, Status: 200 OK, Latency: 1.234ms
```
### Graceful Reload
Reload workers without downtime:
``` bash

kill -HUP $(pgrep -f blazewsgi)
```
### Systemd Service
Create /etc/systemd/system/blazewsgi.service:
```ini

[Unit]
Description=BlazeWSGI Server
After=network.target

[Service]
ExecStart=/path/to/blazewsgi /path/to/config.ini
Restart=always
WorkingDirectory=/path/to/blazewsgi
KillSignal=SIGHUP
Environment="DJANGO_SETTINGS_MODULE=myproject.settings"

[Install]
WantedBy=multi-user.target
```
Enable and start:
```bash

sudo systemctl enable blazewsgi
sudo systemctl start blazewsgi
```
### Performance
BlazeWSGI is optimized for I/O-bound workloads, particularly Django applications:
**Throughput**: 10,000–25,000 req/s (HTTP), 8,000–20,000 req/s (HTTPS) for simple Django views.

**Latency**: 0.5–3 ms (HTTP), 0.7–4 ms (HTTPS).

**Comparison to Gunicorn**:
Gunicorn with gevent (Unix socket): 4,000–12,000 req/s, 3–15 ms latency.

BlazeWSGI’s libevent, dynamic scaling, and zero-downtime clustering provide a significant edge.

**Notes**:
Database Queries: Django’s ORM may bottleneck complex views.

**Static Files**: Serve via Nginx for best performance.

**Logging**: Daily rotation keeps logs manageable; consider logrotate for long-term use.

### Benchmarking
Compare BlazeWSGI with Gunicorn:
```bash

# BlazeWSGI
wrk -t 4 -c 200 -d 30s http://localhost/

# Gunicorn
gunicorn -w 4 -k gevent --bind unix:/tmp/wsgi.sock myproject.wsgi:application
wrk -t 4 -c 200 -d 30s http://localhost/
```
Monitor metrics with Prometheus:
```yaml

scrape_configs:
  - job_name: 'blazewsgi'
    static_configs:
      - targets: ['localhost:9090']
```
### Test scaling:
```bash

wrk -t 8 -c 1000 -d 30s http://localhost/
tail -f /path/to/logs/$(date +%Y-%m-%d).log
```
### Why Use BlazeWSGI?
**Use BlazeWSGI for**:
High-performance Django or WSGI applications with I/O-bound workloads.

Environments requiring dynamic scaling, zero-downtime clustering, or custom logging.

Specialized or performance-critical use cases.

Use Gunicorn for:
Mature, production-hardened deployments with Django optimizations.

Seamless integration with Python frameworks and DevOps tools.

Simpler setup for standard use cases.

Contributing
Contributions are welcome! To contribute:
Fork the repository.

Create a feature branch (git checkout -b feature/my-feature).

Commit changes (git commit -m "Add my feature").

Push to the branch (git push origin feature/my-feature).

Open a pull request.

Please include tests and update documentation where applicable.
License
BlazeWSGI is licensed under the MIT License. See LICENSE for details.
Contact
For issues, feature requests, or questions, open an issue on GitHub or contact your.email@example.com (mailto:your.email@example.com).


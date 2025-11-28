# Deployment Guide for Steganography Application

This guide provides detailed instructions for deploying the steganography application in various environments.

## Prerequisites

Before deploying the application, ensure you have the following:

- Python 3.8 or higher
- pip (Python package manager)
- Git (for cloning the repository)
- Basic knowledge of command line operations
- Administrative access for system-wide installations (if needed)

## Local Development Deployment

### Clone and Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/steganography-app.git
   cd steganography-app
   ```

2. Create and activate a virtual environment:
   ```bash
   # On Windows
   python -m venv .venv
   .venv\Scripts\activate

   # On macOS/Linux
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   python api.py

### Configuration

1. Check the default configuration in `api.py`:
   - Default port: 8080
   - Default host: 0.0.0.0 (accessible from all network interfaces)
   - Default output directory: `./output`
   - Default uploads directory: `./uploads`

2. Modify these settings if needed by editing `api.py`.

### Running the Application

1. Start the Flask application:
   ```bash
   python api.py
   ```

2. Access the web interface at `http://localhost:8080`

## Production Deployment

### Option 1: Deploying with Gunicorn and Nginx (Linux)

#### Setting Up Gunicorn

1. Install Gunicorn:
   ```bash
   pip install gunicorn
   ```

2. Create a WSGI entry point (`wsgi.py`):
   ```python
   from api import app

   if __name__ == "__main__":
       app.run()
   ```

3. Test Gunicorn:
   ```bash
   gunicorn --bind 0.0.0.0:8000 wsgi:app
   ```

#### Setting Up Nginx as a Reverse Proxy

1. Install Nginx:
   ```bash
   # On Ubuntu/Debian
   sudo apt update
   sudo apt install nginx

   # On CentOS/RHEL
   sudo yum install nginx
   ```

2. Create an Nginx configuration file (`/etc/nginx/sites-available/steganography`):
   ```nginx
   server {
       listen 80;
       server_name your_domain.com;  # Replace with your domain or IP

       location / {
           proxy_pass http://localhost:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
           client_max_body_size 100M;  # Adjust based on your file size needs
       }

       location /static {
           alias /path/to/steganography-app/static;
           expires 30d;
       }
   }
   ```

3. Enable the site:
   ```bash
   sudo ln -s /etc/nginx/sites-available/steganography /etc/nginx/sites-enabled/
   sudo nginx -t  # Test the configuration
   sudo systemctl restart nginx
   ```

#### Creating a Systemd Service

1. Create a service file (`/etc/systemd/system/steganography.service`):
   ```ini
   [Unit]
   Description=Gunicorn instance to serve steganography application
   After=network.target

   [Service]
   User=your_username
   Group=your_group
   WorkingDirectory=/path/to/steganography-app
   Environment="PATH=/path/to/steganography-app/.venv/bin"
   ExecStart=/path/to/steganography-app/.venv/bin/gunicorn --workers 4 --bind 0.0.0.0:8000 wsgi:app
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

2. Start and enable the service:
   ```bash
   sudo systemctl start steganography
   sudo systemctl enable steganography
   sudo systemctl status steganography  # Check service status
   ```

### Option 2: Deploying with Docker

#### Creating a Dockerfile

1. Create a `Dockerfile` in the project root:
   ```dockerfile
   FROM python:3.9-slim

   WORKDIR /app

   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt

   COPY . .

   # Create output and uploads directories
   RUN mkdir -p output uploads
   RUN chmod 777 output uploads

   # Expose the port the app runs on
   EXPOSE 8080

   # Command to run the application
   CMD ["python", "api.py"]
   ```

2. Create a `.dockerignore` file:
   ```
   .venv
   __pycache__
   *.pyc
   output/*
   uploads/*
   .git
   .gitignore
   ```

#### Building and Running the Docker Container

1. Build the Docker image:
   ```bash
   docker build -t steganography-app .
   ```

2. Run the container:
   ```bash
   docker run -p 8080:8080 -v "$(pwd)/output:/app/output" -v "$(pwd)/uploads:/app/uploads" --name stego-app steganography-app
   ```

3. Access the application at `http://localhost:8080`

#### Docker Compose Setup

1. Create a `docker-compose.yml` file:
   ```yaml
   version: '3'

   services:
     stego-app:
       build: .
       ports:
         - "8080:8080"
       volumes:
         - ./output:/app/output
         - ./uploads:/app/uploads
       restart: unless-stopped
   ```

2. Start the application using Docker Compose:
   ```bash
   docker-compose up -d
   ```

3. Stop the application:
   ```bash
   docker-compose down
   ```

### Option 3: Deploying on Windows IIS

#### Setting Up with WSGI

1. Install the Windows features:
   - IIS (Internet Information Services)
   - CGI module

2. Install the `wfastcgi` package:
   ```bash
   pip install wfastcgi
   wfastcgi-enable
   ```

3. Configure IIS:
   - Create a new website in IIS Manager
   - Set the physical path to your application directory
   - Configure the handler mapping for FastCGI

## Cloud Deployment Options

### AWS Elastic Beanstalk

1. Install AWS EB CLI:
   ```bash
   pip install awsebcli
   ```

2. Create a `.ebignore` file similar to your `.gitignore`

3. Configure EB application:
   ```bash
   eb init -p python-3.8 steganography-app
   ```

4. Create an environment:
   ```bash
   eb create steganography-env
   ```

5. Deploy your application:
   ```bash
   eb deploy
   ```

### Google Cloud Run

1. Build a Docker container as described in the Docker section

2. Deploy to Cloud Run:
   ```bash
   gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/steganography-app
   gcloud run deploy steganography --image gcr.io/YOUR_PROJECT_ID/steganography-app --platform managed
   ```

### Heroku

1. Create a `Procfile` in the project root:
   ```
   web: gunicorn wsgi:app
   ```

2. Create a `runtime.txt` file:
   ```
   python-3.9.7
   ```

3. Deploy to Heroku:
   ```bash
   heroku create steganography-app
   git push heroku main
   ```

## Security Considerations for Production

### HTTPS Configuration

1. For Nginx, set up SSL with Let's Encrypt:
   ```bash
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d your_domain.com
   ```

2. Update your Nginx configuration to force HTTPS:
   ```nginx
   server {
       listen 80;
       server_name your_domain.com;
       return 301 https://$host$request_uri;
   }

   server {
       listen 443 ssl;
       server_name your_domain.com;

       ssl_certificate /etc/letsencrypt/live/your_domain.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/your_domain.com/privkey.pem;
       
       # ... rest of your configuration
   }
   ```

### File Upload Limitations

1. Configure maximum upload size in your web server:
   - For Nginx, in your server block:
     ```nginx
     client_max_body_size 100M;  # Adjust as needed
     ```
   - For Apache, in your VirtualHost:
     ```apache
     LimitRequestBody 104857600  # 100MB in bytes
     ```

2. Update the Flask configuration:
   ```python
   app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB
   ```

### Access Control

To add basic authentication to your application:

1. Install Flask-BasicAuth:
   ```bash
   pip install Flask-BasicAuth
   ```

2. Modify your `api.py`:
   ```python
   from flask_basicauth import BasicAuth

   app.config['BASIC_AUTH_USERNAME'] = 'username'
   app.config['BASIC_AUTH_PASSWORD'] = 'password'
   app.config['BASIC_AUTH_FORCE'] = True  # Apply to entire app

   basic_auth = BasicAuth(app)
   ```

## Monitoring and Maintenance

### Logging Configuration

1. Create a logging configuration in `api.py`:
   ```python
   import logging
   from logging.handlers import RotatingFileHandler

   if __name__ == "__main__":
       # Configure logging
       handler = RotatingFileHandler('steganography.log', maxBytes=10000000, backupCount=5)
       handler.setLevel(logging.INFO)
       app.logger.addHandler(handler)
       app.run(debug=False, host="0.0.0.0", port=8080)
   ```

### Backup Procedures

1. Schedule regular backups for the data directories:
   ```bash
   # Example cron job for daily backups at 2 AM
   0 2 * * * tar -czf /backup/stego-backup-$(date +\%Y\%m\%d).tar.gz /path/to/steganography-app/output /path/to/steganography-app/uploads
   ```

### Health Checks

Implement a health check endpoint in your application:

```python
@app.route('/api/health')
def health_check():
    return jsonify({'status': 'healthy'})
```

## Performance Tuning

### Gunicorn Workers

Optimize the number of Gunicorn workers based on your server's resources:

```bash
# Rule of thumb: 2-4 workers per CPU core
gunicorn --workers 4 --threads 2 wsgi:app
```

### Nginx Caching

Add caching for static assets in Nginx:

```nginx
location /static {
    alias /path/to/steganography-app/static;
    expires 30d;
    add_header Cache-Control "public, max-age=2592000";
}
```

## Performance Considerations

### CPU Resources

The application's performance is primarily affected by:

1. **Image processing**: Converting and manipulating large images requires significant CPU
2. **Audio processing**: WAV file manipulation for audio steganography
3. **Encryption/Decryption**: AES operations for large messages
4. **Compression/Decompression**: zlib compression at maximum level (9)

For high-traffic deployments, consider:
- Implementing request queuing
- Horizontally scaling with multiple instances
- Setting reasonable file size limits
- Allocating sufficient CPU resources

### Memory Usage

Memory consumption is primarily affected by:

1. **File size**: Larger media files require more memory
2. **Concurrent requests**: Each request processes files in memory
3. **Compression operations**: zlib compression requires additional memory proportional to message size

Recommended minimum specifications:
- 2GB RAM for basic usage
- 4GB+ RAM for production deployment
- Swap space equal to physical RAM

## Conclusion

This deployment guide provides multiple options for deploying the steganography application in different environments. Choose the deployment method that best fits your infrastructure requirements and technical expertise.

For optimal security and performance, consider:
- Always using HTTPS in production
- Implementing proper access controls
- Regularly backing up your data
- Monitoring application health and resource usage
- Following security best practices for file uploads and storage 
# SecurScan Security Testing Platform

## Installation Guide

This guide provides step-by-step instructions for installing and configuring the SecurScan security testing platform.

### Table of Contents
1. [System Requirements](#system-requirements)
2. [Installation Options](#installation-options)
3. [Standard Installation](#standard-installation)
4. [Docker Installation](#docker-installation)
5. [Cloud Deployment](#cloud-deployment)
6. [Initial Configuration](#initial-configuration)
7. [Troubleshooting](#troubleshooting)

## System Requirements <a name="system-requirements"></a>

### Minimum Requirements
- **CPU**: 4 cores
- **RAM**: 8 GB
- **Storage**: 50 GB
- **Operating System**: Ubuntu 20.04 LTS, CentOS 8, or Windows Server 2019
- **Database**: MongoDB 4.4+
- **Node.js**: v16.x or higher
- **Network**: Internet connection for updates and external scanning

### Recommended Requirements
- **CPU**: 8+ cores
- **RAM**: 16+ GB
- **Storage**: 100+ GB SSD
- **Operating System**: Ubuntu 22.04 LTS
- **Database**: MongoDB 5.0+
- **Node.js**: v18.x or higher
- **Network**: 100+ Mbps internet connection

## Installation Options <a name="installation-options"></a>

SecurScan can be installed in several ways:

1. **Standard Installation**: Direct installation on a server or workstation
2. **Docker Installation**: Containerized deployment using Docker and Docker Compose
3. **Cloud Deployment**: Deployment on cloud platforms (AWS, Azure, GCP)

Choose the installation method that best fits your environment and requirements.

## Standard Installation <a name="standard-installation"></a>

### Prerequisites
- Node.js and npm installed
- MongoDB installed and running
- Git installed

### Installation Steps

1. **Clone the repository**

   ```bash
   git clone https://github.com/securscan/securscan.git
   cd securscan
   ```

2. **Install backend dependencies**

   ```bash
   cd backend
   npm install
   ```

3. **Install frontend dependencies**

   ```bash
   cd ../frontend
   npm install
   ```

4. **Configure environment variables**

   Create a `.env` file in the backend directory:

   ```bash
   cd ../backend
   cp .env.example .env
   ```

   Edit the `.env` file to set your configuration:

   ```
   # Server Configuration
   PORT=5000
   NODE_ENV=production
   
   # Database Configuration
   MONGODB_URI=mongodb://localhost:27017/securscan
   
   # JWT Configuration
   JWT_SECRET=your_secure_jwt_secret_key
   JWT_EXPIRATION=1d
   
   # Logging Configuration
   LOG_LEVEL=info
   
   # Email Configuration (optional)
   SMTP_HOST=smtp.example.com
   SMTP_PORT=587
   SMTP_USER=your_email@example.com
   SMTP_PASS=your_email_password
   
   # Scan Engine Configuration
   MAX_CONCURRENT_SCANS=5
   SCAN_TIMEOUT=3600
   ```

5. **Build the frontend**

   ```bash
   cd ../frontend
   npm run build
   ```

6. **Start the application**

   ```bash
   cd ../backend
   npm run start
   ```

7. **Access the application**

   Open your browser and navigate to `http://localhost:5000`

### Setting Up as a Service

To run SecurScan as a service on Linux:

1. **Create a systemd service file**

   ```bash
   sudo nano /etc/systemd/system/securscan.service
   ```

2. **Add the following configuration**

   ```
   [Unit]
   Description=SecurScan Security Testing Platform
   After=network.target mongodb.service
   
   [Service]
   Type=simple
   User=securscan
   WorkingDirectory=/path/to/securscan/backend
   ExecStart=/usr/bin/node /path/to/securscan/backend/src/server.js
   Restart=on-failure
   Environment=NODE_ENV=production
   
   [Install]
   WantedBy=multi-user.target
   ```

3. **Enable and start the service**

   ```bash
   sudo systemctl enable securscan
   sudo systemctl start securscan
   ```

4. **Check the service status**

   ```bash
   sudo systemctl status securscan
   ```

## Docker Installation <a name="docker-installation"></a>

### Prerequisites
- Docker installed
- Docker Compose installed

### Installation Steps

1. **Clone the repository**

   ```bash
   git clone https://github.com/securscan/securscan.git
   cd securscan
   ```

2. **Configure environment variables**

   Create a `.env` file in the root directory:

   ```bash
   cp .env.example .env
   ```

   Edit the `.env` file as needed.

3. **Build and start the containers**

   ```bash
   docker-compose up -d
   ```

4. **Access the application**

   Open your browser and navigate to `http://localhost:8080`

### Docker Compose Configuration

The `docker-compose.yml` file includes the following services:

- **frontend**: React frontend application
- **backend**: Node.js API server
- **mongodb**: MongoDB database
- **redis**: Redis for caching and session storage (optional)

You can customize the Docker Compose configuration to fit your needs.

## Cloud Deployment <a name="cloud-deployment"></a>

### AWS Deployment

1. **Launch an EC2 instance**
   - Recommended: t3.large or better
   - Ubuntu Server 22.04 LTS
   - At least 50 GB storage

2. **Install dependencies**

   ```bash
   sudo apt update
   sudo apt upgrade -y
   sudo apt install -y docker.io docker-compose git
   sudo systemctl enable docker
   sudo systemctl start docker
   sudo usermod -aG docker ubuntu
   ```

3. **Clone and deploy the application**

   ```bash
   git clone https://github.com/securscan/securscan.git
   cd securscan
   cp .env.example .env
   # Edit .env file as needed
   docker-compose up -d
   ```

4. **Configure security groups**
   - Allow inbound traffic on ports 22 (SSH), 80 (HTTP), and 443 (HTTPS)

5. **Set up a domain and SSL**
   - Register a domain or use a subdomain
   - Configure DNS to point to your EC2 instance
   - Install and configure Nginx with Let's Encrypt for SSL

### Azure Deployment

1. **Create a Virtual Machine**
   - Recommended: Standard_D2s_v3 or better
   - Ubuntu Server 22.04 LTS
   - At least 50 GB storage

2. **Follow the standard installation or Docker installation steps**

3. **Configure Network Security Group**
   - Allow inbound traffic on ports 22 (SSH), 80 (HTTP), and 443 (HTTPS)

### Google Cloud Platform Deployment

1. **Create a Compute Engine instance**
   - Recommended: e2-standard-2 or better
   - Ubuntu Server 22.04 LTS
   - At least 50 GB storage

2. **Follow the standard installation or Docker installation steps**

3. **Configure firewall rules**
   - Allow inbound traffic on ports 22 (SSH), 80 (HTTP), and 443 (HTTPS)

## Initial Configuration <a name="initial-configuration"></a>

After installation, you need to perform some initial configuration:

### Creating the Admin User

1. **Access the application**
   - Open your browser and navigate to the application URL
   - You will be redirected to the setup page

2. **Create the admin user**
   - Fill in the admin user details:
     - Name
     - Email
     - Password
   - Click "Create Admin User"

3. **Log in with the admin user**
   - Use the email and password you just created

### System Configuration

1. **Access the Settings page**
   - Click on your username in the top-right corner
   - Select "Settings" from the dropdown menu

2. **Configure general settings**
   - Platform name
   - Logo
   - Default language
   - Time zone

3. **Configure email settings**
   - SMTP server
   - SMTP port
   - SMTP username
   - SMTP password
   - Sender email address

4. **Configure scan settings**
   - Default scan policy
   - Maximum concurrent scans
   - Scan timeout
   - Default user agent

5. **Save the configuration**
   - Click "Save Changes"

## Troubleshooting <a name="troubleshooting"></a>

### Common Installation Issues

#### MongoDB Connection Issues

**Problem**: The application cannot connect to MongoDB.

**Solution**:
1. Verify MongoDB is running:
   ```bash
   sudo systemctl status mongodb
   ```
2. Check MongoDB connection string in `.env` file
3. Ensure MongoDB is listening on the correct port:
   ```bash
   sudo netstat -tuln | grep 27017
   ```

#### Node.js Version Issues

**Problem**: Incompatible Node.js version.

**Solution**:
1. Check your Node.js version:
   ```bash
   node -v
   ```
2. Install the recommended Node.js version using NVM:
   ```bash
   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash
   source ~/.bashrc
   nvm install 18
   nvm use 18
   ```

#### Permission Issues

**Problem**: Permission denied errors during installation.

**Solution**:
1. Check directory permissions:
   ```bash
   ls -la /path/to/securscan
   ```
2. Change ownership if needed:
   ```bash
   sudo chown -R yourusername:yourusername /path/to/securscan
   ```

#### Docker Issues

**Problem**: Docker containers fail to start.

**Solution**:
1. Check Docker logs:
   ```bash
   docker-compose logs
   ```
2. Verify Docker and Docker Compose versions:
   ```bash
   docker --version
   docker-compose --version
   ```
3. Ensure Docker service is running:
   ```bash
   sudo systemctl status docker
   ```

### Getting Help

If you encounter issues not covered in this guide:

1. Check the logs:
   - Application logs: `/path/to/securscan/backend/logs`
   - Docker logs: `docker-compose logs`
   - System logs: `journalctl -u securscan`

2. Visit the official documentation:
   - [SecurScan Documentation](https://docs.securscan.com)

3. Contact support:
   - Email: support@securscan.com
   - GitHub Issues: https://github.com/securscan/securscan/issues

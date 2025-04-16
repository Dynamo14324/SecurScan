/**
 * Vulnerable Application Environment
 * 
 * This module sets up intentionally vulnerable applications for security testing practice.
 * It includes various technology stacks and common vulnerabilities for comprehensive learning.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { spawn } = require('child_process');

class VulnerableApplicationEnvironment {
  constructor(options = {}) {
    this.options = {
      baseDir: options.baseDir || './vulnerable-apps',
      appsToInstall: options.appsToInstall || ['dvwa', 'juice-shop', 'webgoat', 'vulnerable-node', 'vulnerable-flask'],
      dockerSupport: options.dockerSupport !== false,
      ...options
    };
    
    // Create base directory if it doesn't exist
    if (!fs.existsSync(this.options.baseDir)) {
      fs.mkdirSync(this.options.baseDir, { recursive: true });
    }
    
    this.runningApps = new Map();
  }

  /**
   * Setup the vulnerable application environment
   * @returns {Promise<Object>} - Setup result
   */
  async setup() {
    console.log('Setting up vulnerable application environment...');
    
    const results = {
      success: true,
      installedApps: [],
      failedApps: [],
      messages: []
    };
    
    // Check if Docker is available if Docker support is enabled
    if (this.options.dockerSupport) {
      try {
        execSync('docker --version', { stdio: 'pipe' });
        console.log('Docker is available. Will use Docker for containerized apps.');
        results.messages.push('Docker is available and will be used for containerized applications.');
      } catch (error) {
        console.warn('Docker is not available. Will use local installation methods.');
        results.messages.push('Docker is not available. Using local installation methods instead.');
        this.options.dockerSupport = false;
      }
    }
    
    // Setup each requested application
    for (const app of this.options.appsToInstall) {
      try {
        console.log(`Setting up ${app}...`);
        
        switch (app) {
          case 'dvwa':
            await this.setupDVWA();
            results.installedApps.push('dvwa');
            break;
          case 'juice-shop':
            await this.setupJuiceShop();
            results.installedApps.push('juice-shop');
            break;
          case 'webgoat':
            await this.setupWebGoat();
            results.installedApps.push('webgoat');
            break;
          case 'vulnerable-node':
            await this.setupVulnerableNode();
            results.installedApps.push('vulnerable-node');
            break;
          case 'vulnerable-flask':
            await this.setupVulnerableFlask();
            results.installedApps.push('vulnerable-flask');
            break;
          default:
            console.warn(`Unknown application: ${app}`);
            results.failedApps.push({ app, reason: 'Unknown application' });
        }
        
        console.log(`Successfully set up ${app}.`);
        results.messages.push(`Successfully set up ${app}.`);
      } catch (error) {
        console.error(`Failed to set up ${app}:`, error);
        results.failedApps.push({ app, reason: error.message });
        results.messages.push(`Failed to set up ${app}: ${error.message}`);
      }
    }
    
    // Create a README file with setup instructions
    this.createReadme();
    
    if (results.failedApps.length > 0) {
      results.success = false;
    }
    
    return results;
  }

  /**
   * Setup DVWA (Damn Vulnerable Web Application)
   * @returns {Promise<void>}
   */
  async setupDVWA() {
    const appDir = path.join(this.options.baseDir, 'dvwa');
    
    if (this.options.dockerSupport) {
      // Use Docker for DVWA
      if (!fs.existsSync(appDir)) {
        fs.mkdirSync(appDir, { recursive: true });
      }
      
      // Create docker-compose.yml
      const dockerComposeContent = `
version: '3'
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "8082:80"
    environment:
      - MYSQL_RANDOM_ROOT_PASSWORD=yes
`;
      
      fs.writeFileSync(path.join(appDir, 'docker-compose.yml'), dockerComposeContent);
      
      // Create start script
      const startScriptContent = `#!/bin/bash
cd "$(dirname "$0")"
docker-compose up -d
echo "DVWA is running at http://localhost:8082/"
echo "Default credentials: admin / password"
`;
      
      fs.writeFileSync(path.join(appDir, 'start.sh'), startScriptContent);
      fs.chmodSync(path.join(appDir, 'start.sh'), '755');
      
      // Create stop script
      const stopScriptContent = `#!/bin/bash
cd "$(dirname "$0")"
docker-compose down
`;
      
      fs.writeFileSync(path.join(appDir, 'stop.sh'), stopScriptContent);
      fs.chmodSync(path.join(appDir, 'stop.sh'), '755');
      
      console.log('DVWA setup complete with Docker.');
    } else {
      // Use git clone for DVWA
      if (!fs.existsSync(appDir)) {
        execSync('git clone https://github.com/digininja/DVWA.git ' + appDir);
      }
      
      // Create config file
      const configFile = path.join(appDir, 'config', 'config.inc.php');
      if (!fs.existsSync(configFile)) {
        const configSampleFile = path.join(appDir, 'config', 'config.inc.php.dist');
        if (fs.existsSync(configSampleFile)) {
          let configContent = fs.readFileSync(configSampleFile, 'utf8');
          configContent = configContent.replace(/^\$_DVWA\[ 'db_password' \] = '.*?';/m, "$_DVWA[ 'db_password' ] = '';");
          fs.writeFileSync(configFile, configContent);
        }
      }
      
      // Create start script for PHP built-in server
      const startScriptContent = `#!/bin/bash
cd "$(dirname "$0")"
php -S 0.0.0.0:8082 &
echo "DVWA is running at http://localhost:8082/"
echo "Default credentials: admin / password"
echo "You need to set up the database through the web interface on first run."
`;
      
      fs.writeFileSync(path.join(appDir, 'start.sh'), startScriptContent);
      fs.chmodSync(path.join(appDir, 'start.sh'), '755');
      
      console.log('DVWA setup complete with local installation.');
    }
  }

  /**
   * Setup OWASP Juice Shop
   * @returns {Promise<void>}
   */
  async setupJuiceShop() {
    const appDir = path.join(this.options.baseDir, 'juice-shop');
    
    if (this.options.dockerSupport) {
      // Use Docker for Juice Shop
      if (!fs.existsSync(appDir)) {
        fs.mkdirSync(appDir, { recursive: true });
      }
      
      // Create docker-compose.yml
      const dockerComposeContent = `
version: '3'
services:
  juice-shop:
    image: bkimminich/juice-shop
    ports:
      - "3000:3000"
`;
      
      fs.writeFileSync(path.join(appDir, 'docker-compose.yml'), dockerComposeContent);
      
      // Create start script
      const startScriptContent = `#!/bin/bash
cd "$(dirname "$0")"
docker-compose up -d
echo "OWASP Juice Shop is running at http://localhost:3000/"
`;
      
      fs.writeFileSync(path.join(appDir, 'start.sh'), startScriptContent);
      fs.chmodSync(path.join(appDir, 'start.sh'), '755');
      
      // Create stop script
      const stopScriptContent = `#!/bin/bash
cd "$(dirname "$0")"
docker-compose down
`;
      
      fs.writeFileSync(path.join(appDir, 'stop.sh'), stopScriptContent);
      fs.chmodSync(path.join(appDir, 'stop.sh'), '755');
      
      console.log('OWASP Juice Shop setup complete with Docker.');
    } else {
      // Use npm for Juice Shop
      if (!fs.existsSync(appDir)) {
        fs.mkdirSync(appDir, { recursive: true });
        
        // Create package.json
        const packageJsonContent = `{
  "name": "juice-shop-local",
  "version": "1.0.0",
  "description": "OWASP Juice Shop local installation",
  "main": "index.js",
  "scripts": {
    "start": "npx @juice-shop/juice-shop"
  },
  "dependencies": {
    "@juice-shop/juice-shop": "latest"
  }
}`;
        
        fs.writeFileSync(path.join(appDir, 'package.json'), packageJsonContent);
        
        // Install dependencies
        execSync('npm install', { cwd: appDir });
      }
      
      // Create start script
      const startScriptContent = `#!/bin/bash
cd "$(dirname "$0")"
npm start &
echo "OWASP Juice Shop is running at http://localhost:3000/"
`;
      
      fs.writeFileSync(path.join(appDir, 'start.sh'), startScriptContent);
      fs.chmodSync(path.join(appDir, 'start.sh'), '755');
      
      console.log('OWASP Juice Shop setup complete with local installation.');
    }
  }

  /**
   * Setup WebGoat
   * @returns {Promise<void>}
   */
  async setupWebGoat() {
    const appDir = path.join(this.options.baseDir, 'webgoat');
    
    if (this.options.dockerSupport) {
      // Use Docker for WebGoat
      if (!fs.existsSync(appDir)) {
        fs.mkdirSync(appDir, { recursive: true });
      }
      
      // Create docker-compose.yml
      const dockerComposeContent = `
version: '3'
services:
  webgoat:
    image: webgoat/webgoat
    ports:
      - "8080:8080"
      - "9090:9090"
`;
      
      fs.writeFileSync(path.join(appDir, 'docker-compose.yml'), dockerComposeContent);
      
      // Create start script
      const startScriptContent = `#!/bin/bash
cd "$(dirname "$0")"
docker-compose up -d
echo "WebGoat is running at http://localhost:8080/WebGoat/"
echo "WebWolf is running at http://localhost:9090/WebWolf/"
`;
      
      fs.writeFileSync(path.join(appDir, 'start.sh'), startScriptContent);
      fs.chmodSync(path.join(appDir, 'start.sh'), '755');
      
      // Create stop script
      const stopScriptContent = `#!/bin/bash
cd "$(dirname "$0")"
docker-compose down
`;
      
      fs.writeFileSync(path.join(appDir, 'stop.sh'), stopScriptContent);
      fs.chmodSync(path.join(appDir, 'stop.sh'), '755');
      
      console.log('WebGoat setup complete with Docker.');
    } else {
      // Use Java for WebGoat
      if (!fs.existsSync(appDir)) {
        fs.mkdirSync(appDir, { recursive: true });
      }
      
      // Download WebGoat jar
      const webgoatJar = path.join(appDir, 'webgoat.jar');
      if (!fs.existsSync(webgoatJar)) {
        execSync('curl -L -o webgoat.jar https://github.com/WebGoat/WebGoat/releases/download/v8.2.2/webgoat-server-8.2.2.jar', { cwd: appDir });
      }
      
      // Create start script
      const startScriptContent = `#!/bin/bash
cd "$(dirname "$0")"
java -jar webgoat.jar --server.port=8080 --server.address=0.0.0.0 &
echo "WebGoat is running at http://localhost:8080/WebGoat/"
`;
      
      fs.writeFileSync(path.join(appDir, 'start.sh'), startScriptContent);
      fs.chmodSync(path.join(appDir, 'start.sh'), '755');
      
      console.log('WebGoat setup complete with local installation.');
    }
  }

  /**
   * Setup Vulnerable Node.js Application
   * @returns {Promise<void>}
   */
  async setupVulnerableNode() {
    const appDir = path.join(this.options.baseDir, 'vulnerable-node');
    
    if (!fs.existsSync(appDir)) {
      fs.mkdirSync(appDir, { recursive: true });
      
      // Create a simple vulnerable Node.js application
      const appContent = `
const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
const port = 3001;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Vulnerable to XSS
app.get('/search', (req, res) => {
  const query = req.query.q || '';
  res.send(\`
    <html>
      <head><title>Search Results</title></head>
      <body>
        <h1>Search Results for: \${query}</h1>
        <p>No results found for \${query}</p>
        <a href="/">Back to Home</a>
      </body>
    </html>
  \`);
});

// Vulnerable to SQL Injection (simulated)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // This is a simulation of SQL injection vulnerability
  // In a real app, this would be a database query
  if (username === 'admin' && password === 'password') {
    res.send('Login successful!');
  } else if (username.includes("' OR '1'='1")) {
    res.send('SQL Injection successful! All user data: [simulated data]');
  } else {
    res.send('Login failed.');
  }
});

// Vulnerable to Command Injection
app.get('/ping', (req, res) => {
  const host = req.query.host || 'localhost';
  
  exec(\`ping -c 3 \${host}\`, (error, stdout, stderr) => {
    if (error) {
      res.send(\`Error: \${error.message}\`);
      return;
    }
    if (stderr) {
      res.send(\`Error: \${stderr}\`);
      return;
    }
    res.send(\`<pre>\${stdout}</pre>\`);
  });
});

// Vulnerable to Path Traversal
app.get('/file', (req, res) => {
  const filename = req.query.name || 'default.txt';
  
  try {
    const content = fs.readFileSync(path.join(__dirname, 'files', filename), 'utf8');
    res.send(\`<pre>\${content}</pre>\`);
  } catch (error) {
    res.send(\`Error: \${error.message}\`);
  }
});

// Vulnerable to Insecure Deserialization
app.post('/deserialize', (req, res) => {
  try {
    const serializedData = req.body.data || '';
    // This is intentionally vulnerable!
    const data = eval('(' + serializedData + ')');
    res.json({ success: true, data });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Create files directory and default file
if (!fs.existsSync(path.join(__dirname, 'files'))) {
  fs.mkdirSync(path.join(__dirname, 'files'));
  fs.writeFileSync(path.join(__dirname, 'files', 'default.txt'), 'This is the default file.');
  fs.writeFileSync(path.join(__dirname, 'files', 'secret.txt'), 'SECRET: This file should not be accessible!');
}

// Create public directory and index.html
if (!fs.existsSync(path.join(__dirname, 'public'))) {
  fs.mkdirSync(path.join(__dirname, 'public'));
  fs.writeFileSync(path.join(__dirname, 'public', 'index.html'), \`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Vulnerable Node.js App</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
          h1 { color: #333; }
          .vulnerability { margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
          h2 { margin-top: 0; }
          form { margin-top: 10px; }
          input, button { padding: 8px; margin-right: 5px; }
        </style>
      </head>
      <body>
        <h1>Vulnerable Node.js Application</h1>
        <p>This application contains intentional security vulnerabilities for testing purposes.</p>
        
        <div class="vulnerability">
          <h2>XSS Vulnerability</h2>
          <p>Try searching with: &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
          <form action="/search" method="get">
            <input type="text" name="q" placeholder="Search term">
            <button type="submit">Search</button>
          </form>
        </div>
        
        <div class="vulnerability">
          <h2>SQL Injection Vulnerability</h2>
          <p>Try logging in with username: ' OR '1'='1</p>
          <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
          </form>
        </div>
        
        <div class="vulnerability">
          <h2>Command Injection Vulnerability</h2>
          <p>Try pinging: localhost; ls -la</p>
          <form action="/ping" method="get">
            <input type="text" name="host" placeholder="Host to ping">
            <button type="submit">Ping</button>
          </form>
        </div>
        
        <div class="vulnerability">
          <h2>Path Traversal Vulnerability</h2>
          <p>Try accessing: ../secret.txt</p>
          <form action="/file" method="get">
            <input type="text" name="name" placeholder="Filename">
            <button type="submit">View File</button>
   
(Content truncated due to size limit. Use line ranges to read in chunks)
/**
 * Isolated Network Environment
 * 
 * This module creates an isolated network environment for security testing
 * without affecting production systems.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { spawn } = require('child_process');

class IsolatedNetworkEnvironment {
  constructor(options = {}) {
    this.options = {
      baseDir: options.baseDir || './isolated-network',
      dockerSupport: options.dockerSupport !== false,
      networkName: options.networkName || 'securscan-network',
      subnetCIDR: options.subnetCIDR || '172.20.0.0/16',
      targetSubnet: options.targetSubnet || '172.20.1.0/24',
      attackerSubnet: options.attackerSubnet || '172.20.2.0/24',
      ...options
    };
    
    // Create base directory if it doesn't exist
    if (!fs.existsSync(this.options.baseDir)) {
      fs.mkdirSync(this.options.baseDir, { recursive: true });
    }
    
    this.runningContainers = new Map();
    this.networkCreated = false;
  }

  /**
   * Setup the isolated network environment
   * @returns {Promise<Object>} - Setup result
   */
  async setup() {
    console.log('Setting up isolated network environment...');
    
    const results = {
      success: true,
      networkCreated: false,
      containersCreated: [],
      failedOperations: [],
      messages: []
    };
    
    // Check if Docker is available
    if (this.options.dockerSupport) {
      try {
        execSync('docker --version', { stdio: 'pipe' });
        console.log('Docker is available. Will use Docker for network isolation.');
        results.messages.push('Docker is available and will be used for network isolation.');
      } catch (error) {
        console.warn('Docker is not available. Will use alternative methods for network isolation.');
        results.messages.push('Docker is not available. Using alternative methods for network isolation.');
        this.options.dockerSupport = false;
      }
    }
    
    if (this.options.dockerSupport) {
      // Create Docker network
      try {
        execSync(`docker network create --subnet=${this.options.subnetCIDR} ${this.options.networkName}`, { stdio: 'pipe' });
        this.networkCreated = true;
        results.networkCreated = true;
        results.messages.push(`Created Docker network: ${this.options.networkName}`);
      } catch (error) {
        // Check if network already exists
        try {
          const networks = execSync('docker network ls', { encoding: 'utf8' });
          if (networks.includes(this.options.networkName)) {
            this.networkCreated = true;
            results.networkCreated = true;
            results.messages.push(`Docker network ${this.options.networkName} already exists.`);
          } else {
            console.error('Failed to create Docker network:', error.message);
            results.failedOperations.push({ operation: 'create_network', reason: error.message });
            results.success = false;
          }
        } catch (listError) {
          console.error('Failed to list Docker networks:', listError.message);
          results.failedOperations.push({ operation: 'list_networks', reason: listError.message });
          results.success = false;
        }
      }
      
      // Create target and attacker containers
      if (this.networkCreated) {
        try {
          // Create target container
          this.createTargetContainer();
          results.containersCreated.push('target');
          results.messages.push('Created target container.');
          
          // Create attacker container
          this.createAttackerContainer();
          results.containersCreated.push('attacker');
          results.messages.push('Created attacker container.');
        } catch (error) {
          console.error('Failed to create containers:', error.message);
          results.failedOperations.push({ operation: 'create_containers', reason: error.message });
          results.success = false;
        }
      }
    } else {
      // Use alternative methods for network isolation
      try {
        this.setupAlternativeNetworkIsolation();
        results.messages.push('Set up alternative network isolation.');
      } catch (error) {
        console.error('Failed to set up alternative network isolation:', error.message);
        results.failedOperations.push({ operation: 'alternative_isolation', reason: error.message });
        results.success = false;
      }
    }
    
    // Create README file with setup instructions
    this.createReadme();
    
    return results;
  }

  /**
   * Create target container
   */
  createTargetContainer() {
    const targetDir = path.join(this.options.baseDir, 'target');
    
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }
    
    // Create docker-compose.yml for target
    const dockerComposeContent = `
version: '3'
networks:
  ${this.options.networkName}:
    external: true

services:
  target-ubuntu:
    image: ubuntu:20.04
    container_name: securscan-target
    hostname: target
    networks:
      ${this.options.networkName}:
        ipv4_address: 172.20.1.10
    volumes:
      - ./shared:/shared
    command: >
      bash -c "
        apt-get update && 
        apt-get install -y openssh-server apache2 python3 python3-pip && 
        service ssh start && 
        service apache2 start && 
        echo 'Welcome to the SecurScan Target Server' > /var/www/html/index.html && 
        mkdir -p /shared && 
        tail -f /dev/null
      "
    cap_add:
      - NET_ADMIN
    restart: unless-stopped

  target-webapp:
    image: vulnerables/web-dvwa
    container_name: securscan-webapp
    hostname: webapp
    networks:
      ${this.options.networkName}:
        ipv4_address: 172.20.1.11
    restart: unless-stopped
`;
    
    fs.writeFileSync(path.join(targetDir, 'docker-compose.yml'), dockerComposeContent);
    
    // Create shared directory
    const sharedDir = path.join(targetDir, 'shared');
    if (!fs.existsSync(sharedDir)) {
      fs.mkdirSync(sharedDir, { recursive: true });
    }
    
    // Create README file in shared directory
    const readmeContent = `# Shared Directory

This directory is shared between the host and the target container.
Files placed here will be accessible from both systems.
`;
    
    fs.writeFileSync(path.join(sharedDir, 'README.md'), readmeContent);
    
    // Create start script
    const startScriptContent = `#!/bin/bash
cd "$(dirname "$0")"
docker-compose up -d
echo "Target containers are running."
echo "Target Ubuntu: 172.20.1.10"
echo "Target WebApp (DVWA): 172.20.1.11"
`;
    
    fs.writeFileSync(path.join(targetDir, 'start.sh'), startScriptContent);
    fs.chmodSync(path.join(targetDir, 'start.sh'), '755');
    
    // Create stop script
    const stopScriptContent = `#!/bin/bash
cd "$(dirname "$0")"
docker-compose down
`;
    
    fs.writeFileSync(path.join(targetDir, 'stop.sh'), stopScriptContent);
    fs.chmodSync(path.join(targetDir, 'stop.sh'), '755');
    
    console.log('Target container setup complete.');
  }

  /**
   * Create attacker container
   */
  createAttackerContainer() {
    const attackerDir = path.join(this.options.baseDir, 'attacker');
    
    if (!fs.existsSync(attackerDir)) {
      fs.mkdirSync(attackerDir, { recursive: true });
    }
    
    // Create Dockerfile for attacker
    const dockerfileContent = `FROM kalilinux/kali-rolling

# Install basic tools
RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    sqlmap \
    metasploit-framework \
    hydra \
    dirb \
    wfuzz \
    whatweb \
    python3 \
    python3-pip \
    git \
    curl \
    wget \
    vim \
    nano \
    iputils-ping \
    net-tools \
    && apt-get clean

# Install Python tools
RUN pip3 install requests beautifulsoup4 scapy

# Set working directory
WORKDIR /root

# Create tools directory
RUN mkdir -p /tools

# Clone some useful security tools
RUN git clone https://github.com/danielmiessler/SecLists.git /tools/SecLists && \
    git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /tools/PayloadsAllTheThings && \
    git clone https://github.com/OWASP/CheatSheetSeries.git /tools/OWASPCheatSheetSeries

# Create shared directory
RUN mkdir -p /shared

# Add a welcome message
RUN echo "echo 'Welcome to the SecurScan Attacker Container'" >> /root/.bashrc && \
    echo "echo 'Target network: 172.20.1.0/24'" >> /root/.bashrc && \
    echo "echo 'Target hosts:'" >> /root/.bashrc && \
    echo "echo '  - Ubuntu: 172.20.1.10'" >> /root/.bashrc && \
    echo "echo '  - WebApp (DVWA): 172.20.1.11'" >> /root/.bashrc

# Keep container running
CMD ["tail", "-f", "/dev/null"]
`;
    
    fs.writeFileSync(path.join(attackerDir, 'Dockerfile'), dockerfileContent);
    
    // Create docker-compose.yml for attacker
    const dockerComposeContent = `
version: '3'
networks:
  ${this.options.networkName}:
    external: true

services:
  attacker:
    build: .
    container_name: securscan-attacker
    hostname: attacker
    networks:
      ${this.options.networkName}:
        ipv4_address: 172.20.2.10
    volumes:
      - ./shared:/shared
    cap_add:
      - NET_ADMIN
    restart: unless-stopped
`;
    
    fs.writeFileSync(path.join(attackerDir, 'docker-compose.yml'), dockerComposeContent);
    
    // Create shared directory
    const sharedDir = path.join(attackerDir, 'shared');
    if (!fs.existsSync(sharedDir)) {
      fs.mkdirSync(sharedDir, { recursive: true });
    }
    
    // Create README file in shared directory
    const readmeContent = `# Shared Directory

This directory is shared between the host and the attacker container.
Files placed here will be accessible from both systems.
`;
    
    fs.writeFileSync(path.join(sharedDir, 'README.md'), readmeContent);
    
    // Create start script
    const startScriptContent = `#!/bin/bash
cd "$(dirname "$0")"
docker-compose build
docker-compose up -d
echo "Attacker container is running at 172.20.2.10"
echo "To access the container shell, run: docker exec -it securscan-attacker bash"
`;
    
    fs.writeFileSync(path.join(attackerDir, 'start.sh'), startScriptContent);
    fs.chmodSync(path.join(attackerDir, 'start.sh'), '755');
    
    // Create stop script
    const stopScriptContent = `#!/bin/bash
cd "$(dirname "$0")"
docker-compose down
`;
    
    fs.writeFileSync(path.join(attackerDir, 'stop.sh'), stopScriptContent);
    fs.chmodSync(path.join(attackerDir, 'stop.sh'), '755');
    
    // Create shell access script
    const shellScriptContent = `#!/bin/bash
docker exec -it securscan-attacker bash
`;
    
    fs.writeFileSync(path.join(attackerDir, 'shell.sh'), shellScriptContent);
    fs.chmodSync(path.join(attackerDir, 'shell.sh'), '755');
    
    console.log('Attacker container setup complete.');
  }

  /**
   * Setup alternative network isolation without Docker
   */
  setupAlternativeNetworkIsolation() {
    const alternativeDir = path.join(this.options.baseDir, 'alternative');
    
    if (!fs.existsSync(alternativeDir)) {
      fs.mkdirSync(alternativeDir, { recursive: true });
    }
    
    // Create README file with instructions for alternative setup
    const readmeContent = `# Alternative Network Isolation

Since Docker is not available, here are alternative methods for network isolation:

## Option 1: Virtual Machines

1. Install VirtualBox or VMware
2. Create two virtual machines:
   - Target VM (e.g., Ubuntu with vulnerable services)
   - Attacker VM (e.g., Kali Linux)
3. Configure network settings:
   - Create a host-only network
   - Connect both VMs to this network
   - Assign static IP addresses to both VMs

## Option 2: Network Namespaces (Linux only)

Use Linux network namespaces to create isolated network environments:

\`\`\`bash
# Create network namespaces
sudo ip netns add target
sudo ip netns add attacker

# Create virtual ethernet pairs
sudo ip link add veth-target type veth peer name veth-target-ns
sudo ip link add veth-attacker type veth peer name veth-attacker-ns

# Connect interfaces to namespaces
sudo ip link set veth-target-ns netns target
sudo ip link set veth-attacker-ns netns attacker

# Configure IP addresses
sudo ip netns exec target ip addr add 172.20.1.10/24 dev veth-target-ns
sudo ip netns exec attacker ip addr add 172.20.2.10/24 dev veth-attacker-ns

# Bring up interfaces
sudo ip link set veth-target up
sudo ip netns exec target ip link set veth-target-ns up
sudo ip link set veth-attacker up
sudo ip netns exec attacker ip link set veth-attacker-ns up

# Create bridge for communication
sudo ip link add br0 type bridge
sudo ip link set br0 up
sudo ip link set veth-target master br0
sudo ip link set veth-attacker master br0
\`\`\`

## Option 3: Use Existing Network with Firewall Rules

If you have multiple machines on the same network, you can use firewall rules to isolate traffic:

\`\`\`bash
# On target machine
sudo iptables -A INPUT -s [attacker_ip] -j ACCEPT
sudo iptables -A INPUT -j DROP

# On attacker machine
sudo iptables -A INPUT -s [target_ip] -j ACCEPT
sudo iptables -A INPUT -j DROP
\`\`\`

## Recommended Approach

The recommended approach is to use virtual machines with VirtualBox or VMware, as this provides the most comprehensive isolation and is easier to set up than network namespaces.
`;
    
    fs.writeFileSync(path.join(alternativeDir, 'README.md'), readmeContent);
    
    // Create setup script for network namespaces
    const setupScriptContent = `#!/bin/bash
# This script sets up network namespaces for isolated testing
# Must be run with sudo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Create network namespaces
ip netns add target
ip netns add attacker

# Create virtual ethernet pairs
ip link add veth-target type veth peer name veth-target-ns
ip link add veth-attacker type veth peer name veth-attacker-ns

# Connect interfaces to namespaces
ip link set veth-target-ns netns target
ip link set veth-attacker-ns netns attacker

# Configure IP addresses
ip netns exec target ip addr add 172.20.1.10/24 dev veth-target-ns
ip netns exec attacker ip addr add 172.20.2.10/24 dev veth-attacker-ns

# Bring up interfaces
ip link set veth-target up
ip netns exec target ip link set veth-target-ns up
ip link set veth-attacker up
ip netns exec attacker ip link set veth-attacker-ns up

# Create bridge for communication
ip link add br0 type bridge
ip link set br0 up
ip link set veth-target master br0
ip link set veth-attacker master br0

echo "Network namespaces setup complete."
echo "To run commands in target namespace: ip netns exec target [command]"
echo "To run commands in attacker namespace: ip netns exec attacker [command]"
echo "To start a shell in target namespace: ip netns exec target bash"
echo "To start a shell in attacker namespace: ip netns exec attacker bash"
`;
    
    fs.writeFileSync(path.join(alternativeDir, 'setup_namespaces.sh'), setupScriptContent);
    fs.chmodSync(path.join(alternativeDir, 'setup_namespaces.sh'), '755');
    
    // Create cleanup script for network namespaces
    const cleanupScriptContent = `#!/bin/bash
# This script cleans up network namespaces
# Must be run with sudo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Remove bridge
ip link delete br0

# Remove network namespaces
ip netns delete target
ip netns delete attacker

echo "Network namespaces cleanup complete."
`;
    
    fs.writeFileSync(path.join(alternativeDir, 'cleanup_namespaces.sh'), cleanupScriptContent);
    fs.chmodSync(path.join(alternativeDir, 'cleanup_namespaces.sh'), '755');
    
    console.log('Alternative network isolation setup complete.');
  }

  /**
   * Create README file with setup instructions
   */
  createReadme() {
    const readmePath = path.join(this.options.baseDir, 'README.md');
    
    const readmeContent = `# Isolated Network Environment

This directory contains an isolated network e
(Content truncated due to size limit. Use line ranges to read in chunks)
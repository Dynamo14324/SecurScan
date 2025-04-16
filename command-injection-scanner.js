/**
 * Command Injection Scanner Module
 * 
 * This module detects command injection vulnerabilities by testing parameters
 * that might be used to execute system commands.
 */

const axios = require('axios');
const { URL } = require('url');
const { generateCommandInjectionPayloads } = require('../utils/payload-generator');
const { analyzeResponse } = require('../utils/response-analyzer');

class CommandInjectionScanner {
  constructor() {
    this.name = 'command-injection-scanner';
    this.description = 'Detects command injection vulnerabilities';
    this.payloads = generateCommandInjectionPayloads();
  }

  /**
   * Scan target for command injection vulnerabilities
   * @param {Object} target - Target information
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async scan(target, options) {
    const findings = [];
    const targetUrl = target.url;
    
    try {
      // Extract parameters from URL
      const url = new URL(targetUrl);
      const params = new URLSearchParams(url.search);
      const paramNames = Array.from(params.keys());
      
      // Identify potential command injection parameters
      const potentialParams = this.identifyPotentialParams(paramNames);
      
      // Test each potential parameter
      for (const param of potentialParams) {
        const originalValue = params.get(param);
        
        for (const payload of this.payloads) {
          // Create a copy of the parameters
          const testParams = new URLSearchParams(params.toString());
          
          // Inject the payload
          testParams.set(param, payload);
          
          // Create the test URL
          const testUrl = new URL(url.toString());
          testUrl.search = testParams.toString();
          
          // Send the request
          const response = await axios.get(testUrl.toString(), {
            timeout: options.timeout,
            headers: {
              'User-Agent': options.userAgent
            },
            validateStatus: () => true, // Accept any status code
            maxRedirects: options.followRedirects ? 5 : 0
          });
          
          // Analyze the response for command injection indicators
          const isVulnerable = this.analyzeForCommandInjection(response, payload);
          
          if (isVulnerable) {
            findings.push({
              type: 'command-injection',
              severity: 'critical',
              confidence: 'medium',
              parameter: param,
              payload: payload,
              url: testUrl.toString(),
              evidence: this.extractEvidence(response),
              description: `Command injection vulnerability detected in parameter '${param}'`,
              remediation: 'Avoid using system commands with user input. If necessary, implement strict input validation, use allowlists, and consider using APIs instead of system commands.',
              cvss: 9.8,
              cwe: 'CWE-78'
            });
            
            // Break the payload loop for this parameter once we find a vulnerability
            break;
          }
        }
      }
      
      // Test for blind command injection using time-based detection
      if (options.checkBlindCommandInjection !== false) {
        const blindFindings = await this.checkBlindCommandInjection(target, potentialParams, options);
        findings.push(...blindFindings);
      }
      
      return findings;
    } catch (error) {
      console.error(`Error in command injection scan: ${error.message}`);
      return findings;
    }
  }

  /**
   * Identify parameters that might be vulnerable to command injection
   * @param {Array} paramNames - List of parameter names
   * @returns {Array} - List of potentially vulnerable parameter names
   */
  identifyPotentialParams(paramNames) {
    const keywords = [
      'cmd', 'command', 'exec', 'execute', 'run', 'system', 'shell',
      'ping', 'query', 'jump', 'code', 'process', 'proc', 'daemon',
      'upload', 'download', 'file', 'document', 'folder', 'directory',
      'delete', 'remove', 'copy', 'move', 'rename', 'chmod', 'chown',
      'path', 'paths', 'filepath', 'dir', 'root', 'app', 'action',
      'do', 'run', 'goto', 'start', 'stop', 'pause', 'resume', 'kill'
    ];
    
    return paramNames.filter(param => {
      const paramLower = param.toLowerCase();
      return keywords.some(keyword => paramLower.includes(keyword));
    });
  }

  /**
   * Analyze response for signs of command injection vulnerability
   * @param {Object} response - Axios response object
   * @param {string} payload - The payload that was sent
   * @returns {boolean} - True if vulnerable, false otherwise
   */
  analyzeForCommandInjection(response, payload) {
    const { data, status } = response;
    const responseText = typeof data === 'string' ? data : JSON.stringify(data);
    
    // Check for command output patterns
    const commandOutputPatterns = [
      'uid=',
      'gid=',
      'groups=',
      'Linux version',
      'Darwin Kernel Version',
      'Windows NT',
      'drwxr-xr-x',
      'drwxrwxrwx',
      '-rwxr-xr-x',
      '-rw-r--r--',
      'Directory of C:\\',
      'Volume in drive C',
      'Volume Serial Number',
      'Directory of',
      'total ',
      'Filesystem',
      'Mounted on',
      'Kernel IP routing table',
      'Iface',
      'Active Internet connections',
      'Proto Recv-Q Send-Q',
      'Active UNIX domain sockets',
      'USER       PID',
      'COMMAND    PID',
      'LISTEN     LISTENING'
    ];
    
    for (const pattern of commandOutputPatterns) {
      if (responseText.includes(pattern)) {
        return true;
      }
    }
    
    // Check for specific command outputs based on the payload
    if (payload.includes('ls') || payload.includes('dir')) {
      if (responseText.match(/([d-][rwx-]{9})\s+\d+\s+\w+\s+\w+\s+\d+\s+\w+\s+\d+\s+[\d:]+\s+[\w.]+/)) {
        return true;
      }
    }
    
    if (payload.includes('id')) {
      if (responseText.match(/uid=\d+\(\w+\)\s+gid=\d+\(\w+\)/)) {
        return true;
      }
    }
    
    if (payload.includes('whoami')) {
      if (responseText.match(/^(root|admin|www-data|nobody|Administrator|SYSTEM|nt authority\\system)$/m)) {
        return true;
      }
    }
    
    if (payload.includes('cat /etc/passwd') || payload.includes('type C:\\Windows\\win.ini')) {
      if (responseText.includes('root:') || responseText.includes('[fonts]')) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Check for blind command injection using time-based detection
   * @param {Object} target - Target information
   * @param {Array} paramNames - List of parameter names to test
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async checkBlindCommandInjection(target, paramNames, options) {
    const findings = [];
    const targetUrl = target.url;
    
    try {
      // Extract parameters from URL
      const url = new URL(targetUrl);
      const params = new URLSearchParams(url.search);
      
      // Time-based payloads
      const timeBasedPayloads = [
        { payload: '; sleep 5 #', delay: 5000 },
        { payload: '& ping -n 5 127.0.0.1 &', delay: 5000 },
        { payload: '| sleep 5 |', delay: 5000 },
        { payload: '`sleep 5`', delay: 5000 },
        { payload: '$(sleep 5)', delay: 5000 },
        { payload: '; ping -c 5 127.0.0.1 ;', delay: 5000 }
      ];
      
      for (const param of paramNames) {
        const originalValue = params.get(param);
        
        // First, measure baseline response time
        const baselineStart = Date.now();
        await axios.get(targetUrl, {
          timeout: options.timeout * 2, // Increase timeout for time-based tests
          headers: {
            'User-Agent': options.userAgent
          },
          validateStatus: () => true
        });
        const baselineTime = Date.now() - baselineStart;
        
        // Test each time-based payload
        for (const { payload, delay } of timeBasedPayloads) {
          // Create a copy of the parameters
          const testParams = new URLSearchParams(params.toString());
          
          // Inject the payload
          testParams.set(param, originalValue + payload);
          
          // Create the test URL
          const testUrl = new URL(url.toString());
          testUrl.search = testParams.toString();
          
          // Send the request and measure time
          const start = Date.now();
          try {
            await axios.get(testUrl.toString(), {
              timeout: options.timeout * 2, // Increase timeout for time-based tests
              headers: {
                'User-Agent': options.userAgent
              },
              validateStatus: () => true
            });
            const responseTime = Date.now() - start;
            
            // If response time is significantly longer than baseline, it might be vulnerable
            if (responseTime > baselineTime + (delay * 0.8)) {
              findings.push({
                type: 'blind-command-injection',
                severity: 'critical',
                confidence: 'medium',
                parameter: param,
                payload: payload,
                url: testUrl.toString(),
                evidence: `Response time: ${responseTime}ms, Baseline: ${baselineTime}ms, Expected delay: ${delay}ms`,
                description: `Blind command injection vulnerability detected in parameter '${param}' using time-based technique`,
                remediation: 'Avoid using system commands with user input. If necessary, implement strict input validation, use allowlists, and consider using APIs instead of system commands.',
                cvss: 9.8,
                cwe: 'CWE-78'
              });
              
              // Break the payload loop for this parameter once we find a vulnerability
              break;
            }
          } catch (error) {
            // Timeout might indicate successful command injection
            if (error.code === 'ECONNABORTED') {
              findings.push({
                type: 'blind-command-injection',
                severity: 'critical',
                confidence: 'medium',
                parameter: param,
                payload: payload,
                url: testUrl.toString(),
                evidence: `Request timed out after ${options.timeout * 2}ms, which might indicate successful command injection`,
                description: `Blind command injection vulnerability detected in parameter '${param}' using time-based technique`,
                remediation: 'Avoid using system commands with user input. If necessary, implement strict input validation, use allowlists, and consider using APIs instead of system commands.',
                cvss: 9.8,
                cwe: 'CWE-78'
              });
              
              // Break the payload loop for this parameter once we find a vulnerability
              break;
            }
          }
        }
      }
      
      return findings;
    } catch (error) {
      console.error(`Error in blind command injection scan: ${error.message}`);
      return findings;
    }
  }

  /**
   * Extract evidence from the response
   * @param {Object} response - Axios response object
   * @returns {string} - Extracted evidence
   */
  extractEvidence(response) {
    const { data, status } = response;
    const responseText = typeof data === 'string' ? data : JSON.stringify(data);
    
    // Return a portion of the response as evidence
    return responseText.substring(0, 200) + (responseText.length > 200 ? '...' : '');
  }
}

module.exports = CommandInjectionScanner;

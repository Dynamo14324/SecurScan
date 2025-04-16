/**
 * Finding Verification System Module
 * 
 * This module provides functionality for verifying security findings
 * to reduce false positives and confirm vulnerabilities.
 */

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const puppeteer = require('puppeteer');

class FindingVerificationSystem extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      timeout: options.timeout || 30000,
      waitTime: options.waitTime || 1000,
      userAgent: options.userAgent || 'SecurScan Pro Security Scanner',
      viewport: options.viewport || { width: 1366, height: 768 },
      screenshotDirectory: options.screenshotDirectory || './screenshots',
      logResults: options.logResults !== false,
      logDirectory: options.logDirectory || './logs',
      verificationThreshold: options.verificationThreshold || 0.8,
      ...options
    };
    
    // Create log directory if it doesn't exist
    if (this.options.logResults && !fs.existsSync(this.options.logDirectory)) {
      fs.mkdirSync(this.options.logDirectory, { recursive: true });
    }
    
    // Create screenshot directory if it doesn't exist
    if (!fs.existsSync(this.options.screenshotDirectory)) {
      fs.mkdirSync(this.options.screenshotDirectory, { recursive: true });
    }
    
    this.browser = null;
    this.verificationResults = new Map();
  }

  /**
   * Initialize the finding verification system
   * @returns {Promise<void>}
   */
  async initialize() {
    if (this.browser) {
      return;
    }
    
    try {
      this.browser = await puppeteer.launch({
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-accelerated-2d-canvas',
          '--disable-gpu',
          '--window-size=1366,768'
        ]
      });
      
      this.emit('initialized');
    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Verify a finding
   * @param {Object} finding - Finding to verify
   * @param {Object} scannerConfig - Scanner configuration
   * @returns {Promise<Object>} - Verification result
   */
  async verifyFinding(finding, scannerConfig) {
    try {
      await this.initialize();
      
      // Check if finding has already been verified
      if (this.verificationResults.has(finding.id)) {
        return this.verificationResults.get(finding.id);
      }
      
      // Select verification method based on finding type
      let verificationResult;
      
      switch (finding.type) {
        case 'sql-injection':
          verificationResult = await this.verifySqlInjection(finding, scannerConfig);
          break;
        case 'xss':
          verificationResult = await this.verifyXss(finding, scannerConfig);
          break;
        case 'csrf':
          verificationResult = await this.verifyCsrf(finding, scannerConfig);
          break;
        case 'ssrf':
          verificationResult = await this.verifySsrf(finding, scannerConfig);
          break;
        case 'xxe':
          verificationResult = await this.verifyXxe(finding, scannerConfig);
          break;
        case 'command-injection':
          verificationResult = await this.verifyCommandInjection(finding, scannerConfig);
          break;
        case 'file-inclusion':
          verificationResult = await this.verifyFileInclusion(finding, scannerConfig);
          break;
        case 'insecure-deserialization':
          verificationResult = await this.verifyInsecureDeserialization(finding, scannerConfig);
          break;
        case 'auth-bypass':
          verificationResult = await this.verifyAuthBypass(finding, scannerConfig);
          break;
        case 'access-control':
          verificationResult = await this.verifyAccessControl(finding, scannerConfig);
          break;
        default:
          verificationResult = await this.verifyGenericFinding(finding, scannerConfig);
      }
      
      // Store verification result
      this.verificationResults.set(finding.id, verificationResult);
      
      // Log verification result
      if (this.options.logResults) {
        this.logVerificationResult(finding, verificationResult);
      }
      
      this.emit('findingVerified', {
        findingId: finding.id,
        verified: verificationResult.verified,
        confidence: verificationResult.confidence
      });
      
      return verificationResult;
    } catch (error) {
      this.emit('error', {
        error: `Error verifying finding: ${error.message}`
      });
      
      const verificationResult = {
        verified: false,
        confidence: 0,
        error: error.message,
        timestamp: Date.now()
      };
      
      // Store verification result
      this.verificationResults.set(finding.id, verificationResult);
      
      return verificationResult;
    }
  }

  /**
   * Verify SQL injection finding
   * @param {Object} finding - Finding to verify
   * @param {Object} scannerConfig - Scanner configuration
   * @returns {Promise<Object>} - Verification result
   */
  async verifySqlInjection(finding, scannerConfig) {
    try {
      // Extract information from finding
      const { url, method, params, headers, payload, evidence } = finding;
      
      if (!url) {
        return {
          verified: false,
          confidence: 0,
          reason: 'Missing URL in finding data',
          timestamp: Date.now()
        };
      }
      
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Set up request interception to modify requests
      await page.setRequestInterception(true);
      
      page.on('request', request => {
        // Only intercept the specific request we're testing
        if (request.url() === url && request.method() === (method || 'GET')) {
          const requestData = {
            method: method || 'GET',
            headers: { ...request.headers(), ...headers }
          };
          
          // Add post data if method is POST
          if (method === 'POST' && params) {
            requestData.postData = typeof params === 'string' ? params : JSON.stringify(params);
          }
          
          request.continue(requestData);
        } else {
          request.continue();
        }
      });
      
      // Navigate to the URL
      let response;
      if (method === 'GET' && params) {
        // Add query parameters to URL
        const urlObj = new URL(url);
        for (const [key, value] of Object.entries(params)) {
          urlObj.searchParams.append(key, value);
        }
        response = await page.goto(urlObj.toString(), {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      } else {
        response = await page.goto(url, {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      }
      
      // Take a screenshot
      const screenshot = path.join(
        this.options.screenshotDirectory,
        `sql_injection_verification_${Date.now()}.png`
      );
      
      await page.screenshot({
        path: screenshot,
        fullPage: true
      });
      
      // Check response for SQL error patterns
      const responseText = await response.text();
      const sqlErrorPatterns = [
        'SQL syntax',
        'mysql_fetch_array',
        'ORA-',
        'Microsoft SQL Server',
        'PostgreSQL',
        'SQLite3',
        'syntax error',
        'unclosed quotation mark',
        'unterminated quoted string',
        'ODBC Driver',
        'SQLSTATE',
        'mysql_num_rows',
        'mysql_query',
        'pg_query',
        'sqlite_query',
        'mysqli_',
        'Warning: mysql_',
        'Warning: pg_',
        'Warning: sqlite_'
      ];
      
      // Check for SQL error patterns in response
      const errorMatches = sqlErrorPatterns.filter(pattern => 
        responseText.includes(pattern)
      );
      
      // Check page content for SQL error patterns
      const pageContent = await page.content();
      const pageMatches = sqlErrorPatterns.filter(pattern => 
        pageContent.includes(pattern)
      );
      
      // Combine matches
      const allMatches = [...new Set([...errorMatches, ...pageMatches])];
      
      // Calculate confidence based on number of matches
      const confidence = Math.min(allMatches.length / 3, 1);
      
      // Check if evidence is present in response or page content
      let evidenceFound = false;
      if (evidence) {
        evidenceFound = responseText.includes(evidence) || pageContent.includes(evidence);
      }
      
      // Determine if finding is verified
      const verified = confidence >= this.options.verificationThreshold || evidenceFound;
      
      // Close the page
      await page.close();
      
      return {
        verified,
        confidence,
        matches: allMatches,
        evidenceFound,
        screenshot,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Error verifying SQL injection:', error);
      
      return {
        verified: false,
        confidence: 0,
        error: error.message,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Verify XSS finding
   * @param {Object} finding - Finding to verify
   * @param {Object} scannerConfig - Scanner configuration
   * @returns {Promise<Object>} - Verification result
   */
  async verifyXss(finding, scannerConfig) {
    try {
      // Extract information from finding
      const { url, method, params, headers, payload, evidence } = finding;
      
      if (!url) {
        return {
          verified: false,
          confidence: 0,
          reason: 'Missing URL in finding data',
          timestamp: Date.now()
        };
      }
      
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Create a unique identifier for this test
      const testId = crypto.randomBytes(8).toString('hex');
      
      // Create a test payload if not provided
      const testPayload = payload || `<script>window.xssTestId="${testId}"</script>`;
      
      // Set up request interception to modify requests
      await page.setRequestInterception(true);
      
      page.on('request', request => {
        // Only intercept the specific request we're testing
        if (request.url().startsWith(url) && request.method() === (method || 'GET')) {
          const requestData = {
            method: method || 'GET',
            headers: { ...request.headers(), ...headers }
          };
          
          // Add post data if method is POST
          if (method === 'POST' && params) {
            const modifiedParams = { ...params };
            
            // Inject XSS payload into each parameter
            for (const key in modifiedParams) {
              modifiedParams[key] = testPayload;
            }
            
            requestData.postData = typeof params === 'string' ? testPayload : JSON.stringify(modifiedParams);
          }
          
          request.continue(requestData);
        } else {
          request.continue();
        }
      });
      
      // Navigate to the URL
      let response;
      if (method === 'GET' && params) {
        // Add query parameters to URL with XSS payload
        const urlObj = new URL(url);
        for (const key in params) {
          urlObj.searchParams.append(key, testPayload);
        }
        response = await page.goto(urlObj.toString(), {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      } else {
        response = await page.goto(url, {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      }
      
      // Take a screenshot
      const screenshot = path.join(
        this.options.screenshotDirectory,
        `xss_verification_${Date.now()}.png`
      );
      
      await page.screenshot({
        path: screenshot,
        fullPage: true
      });
      
      // Check if XSS payload was executed
      const xssExecuted = await page.evaluate(() => {
        return window.xssTestId !== undefined;
      });
      
      // Check if payload is reflected in the page
      const pageContent = await page.content();
      const payloadReflected = pageContent.includes(testPayload);
      
      // Check if evidence is present in page content
      let evidenceFound = false;
      if (evidence) {
        evidenceFound = pageContent.includes(evidence);
      }
      
      // Calculate confidence
      let confidence = 0;
      if (xssExecuted) {
        confidence = 1; // Highest confidence if XSS is executed
      } else if (payloadReflected) {
        confidence = 0.7; // Medium-high confidence if payload is reflected
      } else if (evidenceFound) {
        confidence = 0.5; // Medium confidence if evidence is found
      }
      
      // Determine if finding is verified
      const verified = confidence >= this.options.verificationThreshold;
      
      // Close the page
      await page.close();
      
      return {
        verified,
        confidence,
        xssExecuted,
        payloadReflected,
        evidenceFound,
        screenshot,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Error verifying XSS:', error);
      
      return {
        verified: false,
        confidence: 0,
        error: error.message,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Verify CSRF finding
   * @param {Object} finding - Finding to verify
   * @param {Object} scannerConfig - Scanner configuration
   * @returns {Promise<Object>} - Verification result
   */
  async verifyCsrf(finding, scannerConfig) {
    try {
      // Extract information from finding
      const { url, method, params, headers, evidence, formAction } = finding;
      
      if (!url) {
        return {
          verified: false,
          confidence: 0,
          reason: 'Missing URL in finding data',
          timestamp: Date.now()
        };
      }
      
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Navigate to the URL
      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Take a screenshot
      const screenshot = path.join(
        this.options.screenshotDirectory,
        `csrf_verification_${Date.now()}.png`
      );
      
      await page.screenshot({
        path: screenshot,
        fullPage: true
      });
      
      // Check for CSRF tokens in forms
      const csrfTokens = await page.evaluate(() => {
        const forms = Array.from(document.querySelectorAll('form'));
        const tokens = [];
        
        for (const form of forms) {
          // Check if this is the form we're interested in
          if (form.action && form.method) {
            // Check for hidden input fields that might contain CSRF tokens
            const hiddenInputs = form.querySelectorAll('input[type="hidden"]');
            
            let hasToken = false;
            for (const input of hiddenInputs) {
              const name = input.name.toLowerCase();
              
              if (name.includes('csrf') || 
                  name.includes('token') || 
                  name.includes('nonce') || 
                  name === '_token' || 
                  name === 'authenticity_token') {
                hasToken = true;
                tokens.push({
                  form: form.action,
                  method: form.method,
                  tokenName: input.name,
                  tokenValue: input.value
                });
              }
            }
            
            if (!hasToken) {
              tokens.push({
                form: form.action,
                method: form.method,
                hasToken: false
              });
            }
          }
        }
        
        return tokens;
      });
      
      // Check for CSRF tokens in headers
      const headers_meta = await page.evaluate(() => {
        const metaTags = Array.from(document.querySelectorAll('meta'));
        const csrfHeaders = [];
        
        for (const meta of metaTags) {
          const name = meta.getAttribute('name');
          const content = meta.getAttribute('content');
          
          if (name && content && 
              (name.toLowerCase().includes('csrf') || 
               name.toLowerCase().includes('token'))) {
            csrfHeaders.push({
              name: name,
              value: content
            });
          }
        }
        
        return csrfHeaders;
      });
      
      // Find forms matching the formAction if provided
      let targetForms = csrfTokens;
      if (formAction) {
        targetForms = csrfTokens.filter(token => 
          token.form.includes(formAction)
        );
      }
      
      // Check if any forms are missing CSRF tokens
      const formsWithoutTokens = targetForms.filter(token => !token.hasToken);
      
      // Calculate confidence based on findings
      let confidence = 0;
      
      if (formsWithoutTokens.length > 0) {
        // Higher confidence if specific form is found without token
        confidence = formAction ? 0.9 : 0.7;
      } else if (csrfTokens.length === 0 && headers_meta.length === 0) {
        // Medium confidence if no CSRF protection is found at all
        confidence = 0.5;
      } else if (headers_meta.length === 0) {
        // Lower confidence if only form tokens are found but no header protection
        confidence = 0.3;
      }
      
      // Check if evidence is present in page content
      let evidenceFound = false;
      if (evidence) {
        const pageContent = await page.content();
        evidenceFound = pageContent.includes(evidence);
        if (evidenceFound) {
          confidence = Math.max(confidence, 0.6);
        }
      }
      
      // Determine if finding is verified
      const verified = confidence >= this.options.verificationThreshold;
      
      // Close the page
      await page.close();
      
      return {
        verified,
        confidence,
        formsWithoutTokens,
        csrfHeaders: headers_meta,
        evidenceFound,
        screenshot,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Error verifying CSRF:', error);
      
      return {
        verified: false,
        confidence: 0,
        error: error.message,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Verify SSRF finding
   * @param {Object} finding - Finding to verify
   * @param {Object} scannerConfig - Scanner configuration
   * @returns {Promise<Object>} - Verification result
   */
  async verifySsrf(finding, scannerConfig) {
    try {
      // Extract information from finding
      const { url, method, params, headers, payload, evidence, callbackServer } = finding;
      
      if (!url) {
        return {
          verified: false,
          confidence: 0,
          reason: 'Missing URL in finding data',
          timestamp: Date.now()
        };
      }
      
      // If a callback server is provided, we can verify if it received a request
      if (callbackServer) {
        try {
          // Check if the callback server received a request
          const response = await axios.get(`${callbackServer}/logs`, {
            timeout: 5000
          });
          
          if (response.status === 200 && response.data && response.data.requests) {
            // Check if any requests match our test
            const matchingRequests = response.data.requests.filter(req => 
              req.headers && req.headers['user-agent'] && 
              req.headers['user-agent'].includes('SecurScan')
            );
            
            if (matchingRequests.length > 0) {
              return {
                verified: true,
                confidence: 1,
                callbackReceived: true,
                requests: matchingRequests,
                timestamp: Date.now()
              };
            }
          }
        } catch (error) {
          console.warn('Error checking callback server:', error);
          // Continue with other verification methods
        }
      }
      
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Set up request interception to modify requests
      await page.setRequestInterception(true);
      
      // Track all requests
      const requests = [];
      
      page.on('request', request => {
        requests.push({
          url: request.url(),
          method: request.method(),
          headers: request.headers(),
          postData: request.postData()
        });
        
        request.continue();
      });
      
      // Navigate to the URL
      let response;
      if (method === 'GET' && params) {
        // Add query parameters to URL
        const urlObj = new URL(url);
        for (const [key, value] of Object.entries(params)) {
          urlObj.searchParams.append(key, value);
        }
        response = await page.goto(urlObj.toString(), {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      } else {
        response = await page.goto(url, {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      }
      
      // Take a screenshot
      const screenshot = path.join(
        this.options.screenshotDirectory,
        `ssrf_verification_${Date.now()}.png`
      );
      
      await page.screenshot({
        path: screenshot,
        fullPage: true
      });
      
      // Check for evidence of SSRF
      const responseText = await response.text();
      const pageContent = await page.content();
      
      // Check if evidence is present in response or page content
      let evidenceFound = false;
      if (evidence) {
        evidenceFound = responseText.includes(evidence) || pageContent.includes(evidence);
      }
      
      // Check for suspicious requests to internal networks
      const suspiciousRequests = requests.filter(req => {
        try {
          const reqUrl = new URL(req.url);
          const host = reqUrl.hostname;
          
          // Check for localhost or private IP ranges
          return host === 'localhost' || 
                 host === '127.0.0.1' || 
                 host.startsWith('10.') || 
                 host.startsWith('172.16.') || 
                 host.startsWith('172.17.') || 
                 host.startsWith('172.18.') || 
                 host.startsWith('172.19.') || 
                 host.startsWith('172.20.') || 
                 host.startsWith('172.21.') || 
                 host.startsWith('172.22.') || 
                 host.startsWith('172.23.') || 
                 host.startsWith('172.24.') || 
                 host.startsWith('172.25.') || 
                 host.startsWith('172.26.') || 
                 host.startsWith('172.27.') || 
                 host.startsWith('172.28.') || 
                 host.startsWith('172.29.') || 
                 host.startsWith('172.30.') || 
                 host.startsWith('172.31.') || 
                 host.startsWith('192.168.');
        } catch (error) {
          return false;
        }
      });
      
      // Calculate confidence
      let confidence = 0;
      
      if (suspiciousRequests.length > 0) {
        confidence = 0.9; // High confidence if suspicious requests are found
      } else if (evidenceFound) {
        confidence = 0.7; // Medium-high confidence if evidence is found
      }
      
      // Determine if finding is verified
      const verified = confidence >= this.options.verificationThreshold;
      
      // Close the page
      await page.close();
      
      return {
        verified,
        confidence,
        suspiciousRequests,
        evidenceFound,
        screenshot,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Error verifying SSRF:', error);
      
      return {
        verified: false,
        confidence: 0,
        error: error.message,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Verify XXE finding
   * @param {Object} finding - Finding to verify
   * @param {Object} scannerConfig - Scanner configuration
   * @returns {Promise<Object>} - Verification result
   */
  async verifyXxe(finding, scannerConfig) {
    try {
      // Extract information from finding
      const { url, method, params, headers, payload, evidence, callbackServer } = finding;
      
      if (!url) {
        return {
          verified: false,
          confidence: 0,
          reason: 'Missing URL in finding data',
          timestamp: Date.now()
        };
      }
      
      // If a callback server is provided, we can verify if it received a request
      if (callbackServer) {
        try {
          // Check if the callback server received a request
          const response = await axios.get(`${callbackServer}/logs`, {
            timeout: 5000
          });
          
          if (response.status === 200 && response.data && response.data.requests) {
            // Check if any requests match our test
            const matchingRequests = response.data.requests.filter(req => 
              req.headers && req.headers['user-agent'] && 
              req.headers['user-agent'].includes('SecurScan')
            );
            
            if (matchingRequests.length > 0) {
              return {
                verified: true,
                confidence: 1,
                callbackReceived: true,
                requests: matchingRequests,
                timestamp: Date.now()
              };
            }
          }
        } catch (error) {
          console.warn('Error checking callback server:', error);
          // Continue with other verification methods
        }
      }
      
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Create XXE payload if not provided
      const xxePayload = payload || `<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>`;
      
      // Set up request interception to modify requests
      await page.setRequestInterception(true);
      
      page.on('request', request => {
        // Only intercept the specific request we're testing
        if (request.url() === url && request.method() === (method || 'POST')) {
          const requestData = {
            method: method || 'POST',
            headers: { 
              ...request.headers(), 
              ...headers,
              'Content-Type': 'application/xml'
            },
            postData: xxePayload
          };
          
          request.continue(requestData);
        } else {
          request.continue();
        }
      });
      
      // Navigate to the URL
      const response = await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Take a screenshot
      const screenshot = path.join(
        this.options.screenshotDirectory,
        `xxe_verification_${Date.now()}.png`
      );
      
      await page.screenshot({
        path: screenshot,
        fullPage: true
      });
      
      // Check response for evidence of XXE
      const responseText = await response.text();
      const pageContent = await page.content();
      
      // Check for common patterns that indicate XXE vulnerability
      const xxePatterns = [
        'root:x:0:0',
        '/bin/bash',
        '/usr/sbin',
        'daemon:',
        'nobody:',
        '/etc/passwd',
        'file:///'
      ];
      
      // Check for XXE patterns in response
      const responseMatches = xxePatterns.filter(pattern => 
        responseText.includes(pattern)
      );
      
      // Check for XXE patterns in page content
      const pageMatches = xxePatterns.filter(pattern => 
        pageContent.includes(pattern)
      );
      
      // Combine matches
      const allMatches = [...new Set([...responseMatches, ...pageMatches])];
      
      // Check if evidence is present in response or page content
      let evidenceFound = false;
      if (evidence) {
        evidenceFound = responseText.includes(evidence) || pageContent.includes(evidence);
      }
      
      // Calculate confidence based on number of matches
      let confidence = Math.min(allMatches.length / 2, 1);
      
      if (evidenceFound) {
        confidence = Math.max(confidence, 0.7);
      }
      
      // Determine if finding is verified
      const verified = confidence >= this.options.verificationThreshold;
      
      // Close the page
      await page.close();
      
      return {
        verified,
        confidence,
        matches: allMatches,
        evidenceFound,
        screenshot,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Error verifying XXE:', error);
      
      return {
        verified: false,
        confidence: 0,
        error: error.message,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Verify command injection finding
   * @param {Object} finding - Finding to verify
   * @param {Object} scannerConfig - Scanner configuration
   * @returns {Promise<Object>} - Verification result
   */
  async verifyCommandInjection(finding, scannerConfig) {
    try {
      // Extract information from finding
      const { url, method, params, headers, payload, evidence } = finding;
      
      if (!url) {
        return {
          verified: false,
          confidence: 0,
          reason: 'Missing URL in finding data',
          timestamp: Date.now()
        };
      }
      
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Create command injection payload if not provided
      const cmdPayload = payload || '; echo SecurScanCommandInjectionTest';
      
      // Set up request interception to modify requests
      await page.setRequestInterception(true);
      
      page.on('request', request => {
        // Only intercept the specific request we're testing
        if (request.url().startsWith(url) && request.method() === (method || 'GET')) {
          const requestData = {
            method: method || 'GET',
            headers: { ...request.headers(), ...headers }
          };
          
          // Add post data if method is POST
          if (method === 'POST' && params) {
            const modifiedParams = { ...params };
            
            // Inject command payload into each parameter
            for (const key in modifiedParams) {
              modifiedParams[key] = modifiedParams[key] + cmdPayload;
            }
            
            requestData.postData = typeof params === 'string' ? params + cmdPayload : JSON.stringify(modifiedParams);
          }
          
          request.continue(requestData);
        } else {
          request.continue();
        }
      });
      
      // Navigate to the URL
      let response;
      if (method === 'GET' && params) {
        // Add query parameters to URL with command injection payload
        const urlObj = new URL(url);
        for (const [key, value] of Object.entries(params)) {
          urlObj.searchParams.append(key, value + cmdPayload);
        }
        response = await page.goto(urlObj.toString(), {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      } else {
        response = await page.goto(url, {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      }
      
      // Take a screenshot
      const screenshot = path.join(
        this.options.screenshotDirectory,
        `command_injection_verification_${Date.now()}.png`
      );
      
      await page.screenshot({
        path: screenshot,
        fullPage: true
      });
      
      // Check response for evidence of command injection
      const responseText = await response.text();
      const pageContent = await page.content();
      
      // Check for test marker in response
      const testMarkerFound = responseText.includes('SecurScanCommandInjectionTest') || 
                              pageContent.includes('SecurScanCommandInjectionTest');
      
      // Check for common patterns that indicate command injection
      const cmdPatterns = [
        'uid=',
        'gid=',
        '/bin/',
        '/etc/',
        '/usr/',
        '/var/',
        'total ',
        'drwx',
        '-rwx',
        'Directory of',
        'Volume Serial Number'
      ];
      
      // Check for command patterns in response
      const responseMatches = cmdPatterns.filter(pattern => 
        responseText.includes(pattern)
      );
      
      // Check for command patterns in page content
      const pageMatches = cmdPatterns.filter(pattern => 
        pageContent.includes(pattern)
      );
      
      // Combine matches
      const allMatches = [...new Set([...responseMatches, ...pageMatches])];
      
      // Check if evidence is present in response or page content
      let evidenceFound = false;
      if (evidence) {
        evidenceFound = responseText.includes(evidence) || pageContent.includes(evidence);
      }
      
      // Calculate confidence
      let confidence = 0;
      
      if (testMarkerFound) {
        confidence = 1; // Highest confidence if test marker is found
      } else if (allMatches.length > 0) {
        confidence = Math.min(allMatches.length / 3, 0.9); // High confidence based on pattern matches
      } else if (evidenceFound) {
        confidence = 0.7; // Medium-high confidence if evidence is found
      }
      
      // Determine if finding is verified
      const verified = confidence >= this.options.verificationThreshold;
      
      // Close the page
      await page.close();
      
      return {
        verified,
        confidence,
        testMarkerFound,
        matches: allMatches,
        evidenceFound,
        screenshot,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Error verifying command injection:', error);
      
      return {
        verified: false,
        confidence: 0,
        error: error.message,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Verify file inclusion finding
   * @param {Object} finding - Finding to verify
   * @param {Object} scannerConfig - Scanner configuration
   * @returns {Promise<Object>} - Verification result
   */
  async verifyFileInclusion(finding, scannerConfig) {
    try {
      // Extract information from finding
      const { url, method, params, headers, payload, evidence } = finding;
      
      if (!url) {
        return {
          verified: false,
          confidence: 0,
          reason: 'Missing URL in finding data',
          timestamp: Date.now()
        };
      }
      
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Create file inclusion payloads if not provided
      const lfiPayloads = payload ? [payload] : [
        '../../../etc/passwd',
        '../../../../etc/passwd',
        '../../../../../etc/passwd',
        '../../../../../../etc/passwd',
        '../../../../../../../etc/passwd',
        '../../../../../../../../etc/passwd',
        '../../../../../../../../../etc/passwd',
        'file:///etc/passwd',
        '/etc/passwd',
        'C:\\Windows\\win.ini',
        '..\\..\\..\\..\\..\\..\\Windows\\win.ini'
      ];
      
      // Results for each payload
      const payloadResults = [];
      
      // Test each payload
      for (const lfiPayload of lfiPayloads) {
        // Set up request interception to modify requests
        await page.setRequestInterception(true);
        
        page.on('request', request => {
          // Only intercept the specific request we're testing
          if (request.url().startsWith(url) && request.method() === (method || 'GET')) {
            const requestData = {
              method: method || 'GET',
              headers: { ...request.headers(), ...headers }
            };
            
            // Add post data if method is POST
            if (method === 'POST' && params) {
              const modifiedParams = { ...params };
              
              // Inject LFI payload into each parameter
              for (const key in modifiedParams) {
                modifiedParams[key] = lfiPayload;
              }
              
              requestData.postData = typeof params === 'string' ? lfiPayload : JSON.stringify(modifiedParams);
            }
            
            request.continue(requestData);
          } else {
            request.continue();
          }
        });
        
        // Navigate to the URL
        let response;
        if (method === 'GET' && params) {
          // Add query parameters to URL with LFI payload
          const urlObj = new URL(url);
          for (const key in params) {
            urlObj.searchParams.append(key, lfiPayload);
          }
          response = await page.goto(urlObj.toString(), {
            waitUntil: 'networkidle2',
            timeout: this.options.timeout
          });
        } else {
          response = await page.goto(url, {
            waitUntil: 'networkidle2',
            timeout: this.options.timeout
          });
        }
        
        // Take a screenshot
        const screenshot = path.join(
          this.options.screenshotDirectory,
          `file_inclusion_verification_${Date.now()}_${lfiPayload.replace(/[^a-zA-Z0-9]/g, '_')}.png`
        );
        
        await page.screenshot({
          path: screenshot,
          fullPage: true
        });
        
        // Check response for evidence of file inclusion
        const responseText = await response.text();
        const pageContent = await page.content();
        
        // Check for common patterns that indicate file inclusion
        const lfiPatterns = [
          'root:x:0:0',
          '/bin/bash',
          '/usr/sbin',
          'daemon:',
          'nobody:',
          '[fonts]',
          '[extensions]',
          '[files]',
          '[Mail]',
          'MAPI='
        ];
        
        // Check for LFI patterns in response
        const responseMatches = lfiPatterns.filter(pattern => 
          responseText.includes(pattern)
        );
        
        // Check for LFI patterns in page content
        const pageMatches = lfiPatterns.filter(pattern => 
          pageContent.includes(pattern)
        );
        
        // Combine matches
        const allMatches = [...new Set([...responseMatches, ...pageMatches])];
        
        // Store result for this payload
        payloadResults.push({
          payload: lfiPayload,
          matches: allMatches,
          matchCount: allMatches.length,
          screenshot
        });
        
        // If we found a match, no need to try more payloads
        if (allMatches.length > 0) {
          break;
        }
        
        // Reset request interception for next payload
        await page.setRequestInterception(false);
      }
      
      // Find the payload with the most matches
      const bestResult = payloadResults.reduce((best, current) => 
        current.matchCount > best.matchCount ? current : best
      , { matchCount: 0 });
      
      // Check if evidence is present in response or page content
      let evidenceFound = false;
      if (evidence) {
        const responseText = await page.evaluate(() => document.body.innerText);
        const pageContent = await page.content();
        evidenceFound = responseText.includes(evidence) || pageContent.includes(evidence);
      }
      
      // Calculate confidence
      let confidence = 0;
      
      if (bestResult.matchCount > 0) {
        confidence = Math.min(bestResult.matchCount / 2, 0.9); // High confidence based on pattern matches
      } else if (evidenceFound) {
        confidence = 0.7; // Medium-high confidence if evidence is found
      }
      
      // Determine if finding is verified
      const verified = confidence >= this.options.verificationThreshold;
      
      // Close the page
      await page.close();
      
      return {
        verified,
        confidence,
        bestPayload: bestResult.payload,
        matches: bestResult.matches,
        evidenceFound,
        screenshot: bestResult.screenshot,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Error verifying file inclusion:', error);
      
      return {
        verified: false,
        confidence: 0,
        error: error.message,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Verify insecure deserialization finding
   * @param {Object} finding - Finding to verify
   * @param {Object} scannerConfig - Scanner configuration
   * @returns {Promise<Object>} - Verification result
   */
  async verifyInsecureDeserialization(finding, scannerConfig) {
    try {
      // Extract information from finding
      const { url, method, params, headers, payload, evidence, language } = finding;
      
      if (!url) {
        return {
          verified: false,
          confidence: 0,
          reason: 'Missing URL in finding data',
          timestamp: Date.now()
        };
      }
      
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Create deserialization payload based on language
      let deserPayload = payload;
      if (!deserPayload) {
        switch (language) {
          case 'php':
            deserPayload = 'O:8:"stdClass":1:{s:4:"test";s:28:"SecurScanDeserializationTest";}';
            break;
          case 'java':
            deserPayload = 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAAAIAAAABdAAEdGVzdHQAG1NlY3VyU2NhbkRlc2VyaWFsaXphdGlvblRlc3R4';
            break;
          case 'python':
            deserPayload = 'gASVNAAAAAAAAACMCF9fbWFpbl9flIwEdGVzdJSTlIwbU2VjdXJTY2FuRGVzZXJpYWxpemF0aW9uVGVzdJSFlFKULg==';
            break;
          case 'node':
            deserPayload = '{"test":"SecurScanDeserializationTest"}';
            break;
          default:
            deserPayload = 'O:8:"stdClass":1:{s:4:"test";s:28:"SecurScanDeserializationTest";}';
        }
      }
      
      // Set up request interception to modify requests
      await page.setRequestInterception(true);
      
      page.on('request', request => {
        // Only intercept the specific request we're testing
        if (request.url().startsWith(url) && request.method() === (method || 'POST')) {
          const requestData = {
            method: method || 'POST',
            headers: { ...request.headers(), ...headers }
          };
          
          // Add post data
          if (method === 'POST' || method === 'PUT') {
            const modifiedParams = { ...params };
            
            // Inject deserialization payload into each parameter
            for (const key in modifiedParams) {
              modifiedParams[key] = deserPayload;
            }
            
            requestData.postData = typeof params === 'string' ? deserPayload : JSON.stringify(modifiedParams);
          }
          
          request.continue(requestData);
        } else {
          request.continue();
        }
      });
      
      // Navigate to the URL
      let response;
      if (method === 'GET' && params) {
        // Add query parameters to URL with deserialization payload
        const urlObj = new URL(url);
        for (const key in params) {
          urlObj.searchParams.append(key, deserPayload);
        }
        response = await page.goto(urlObj.toString(), {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      } else {
        response = await page.goto(url, {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      }
      
      // Take a screenshot
      const screenshot = path.join(
        this.options.screenshotDirectory,
        `deserialization_verification_${Date.now()}.png`
      );
      
      await page.screenshot({
        path: screenshot,
        fullPage: true
      });
      
      // Check response for evidence of deserialization
      const responseText = await response.text();
      const pageContent = await page.content();
      
      // Check for test marker in response
      const testMarkerFound = responseText.includes('SecurScanDeserializationTest') || 
                              pageContent.includes('SecurScanDeserializationTest');
      
      // Check for common patterns that indicate deserialization issues
      const deserPatterns = [
        'unserialize',
        'deserialize',
        'ObjectInputStream',
        'readObject',
        'pickle.loads',
        'Marshal.load',
        'yaml.load',
        'TypeError',
        'ClassNotFoundException',
        'SerializationException',
        'readUnshared'
      ];
      
      // Check for deserialization patterns in response
      const responseMatches = deserPatterns.filter(pattern => 
        responseText.includes(pattern)
      );
      
      // Check for deserialization patterns in page content
      const pageMatches = deserPatterns.filter(pattern => 
        pageContent.includes(pattern)
      );
      
      // Combine matches
      const allMatches = [...new Set([...responseMatches, ...pageMatches])];
      
      // Check if evidence is present in response or page content
      let evidenceFound = false;
      if (evidence) {
        evidenceFound = responseText.includes(evidence) || pageContent.includes(evidence);
      }
      
      // Calculate confidence
      let confidence = 0;
      
      if (testMarkerFound) {
        confidence = 1; // Highest confidence if test marker is found
      } else if (allMatches.length > 0) {
        confidence = Math.min(allMatches.length / 2, 0.9); // High confidence based on pattern matches
      } else if (evidenceFound) {
        confidence = 0.7; // Medium-high confidence if evidence is found
      }
      
      // Determine if finding is verified
      const verified = confidence >= this.options.verificationThreshold;
      
      // Close the page
      await page.close();
      
      return {
        verified,
        confidence,
        testMarkerFound,
        matches: allMatches,
        evidenceFound,
        screenshot,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Error verifying insecure deserialization:', error);
      
      return {
        verified: false,
        confidence: 0,
        error: error.message,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Verify authentication bypass finding
   * @param {Object} finding - Finding to verify
   * @param {Object} scannerConfig - Scanner configuration
   * @returns {Promise<Object>} - Verification result
   */
  async verifyAuthBypass(finding, scannerConfig) {
    try {
      // Extract information from finding
      const { url, method, params, headers, payload, evidence, protectedUrl, bypassTechnique } = finding;
      
      if (!url || !protectedUrl) {
        return {
          verified: false,
          confidence: 0,
          reason: 'Missing URL or protected URL in finding data',
          timestamp: Date.now()
        };
      }
      
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // First, try to access the protected URL directly to confirm it's protected
      let isProtected = true;
      try {
        const protectedResponse = await page.goto(protectedUrl, {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
        
        // Check if we were redirected to a login page
        const finalUrl = page.url();
        if (finalUrl.includes('login') || finalUrl.includes('signin') || finalUrl.includes('auth')) {
          isProtected = true;
        } else {
          // Check for login forms or authentication elements
          const hasLoginForm = await page.evaluate(() => {
            const forms = Array.from(document.querySelectorAll('form'));
            return forms.some(form => {
              const formHtml = form.outerHTML.toLowerCase();
              return formHtml.includes('login') || 
                     formHtml.includes('signin') || 
                     formHtml.includes('username') || 
                     formHtml.includes('password');
            });
          });
          
          if (hasLoginForm) {
            isProtected = true;
          } else {
            // Check response status
            isProtected = protectedResponse.status() === 401 || 
                          protectedResponse.status() === 403 || 
                          protectedResponse.status() === 302;
          }
        }
      } catch (error) {
        console.warn('Error accessing protected URL:', error);
        // Assume it's protected if we can't access it
        isProtected = true;
      }
      
      if (!isProtected) {
        // If the URL is not actually protected, we can't verify auth bypass
        await page.close();
        
        return {
          verified: false,
          confidence: 0,
          reason: 'Protected URL is not actually protected',
          timestamp: Date.now()
        };
      }
      
      // Now try the bypass technique
      let bypassHeaders = { ...headers };
      let bypassParams = { ...params };
      let bypassUrl = url;
      
      // Apply bypass technique
      switch (bypassTechnique) {
        case 'header-manipulation':
          // Add or modify headers that might bypass authentication
          bypassHeaders['X-Original-URL'] = protectedUrl;
          bypassHeaders['X-Rewrite-URL'] = protectedUrl;
          break;
        case 'parameter-manipulation':
          // Add parameters that might bypass authentication checks
          if (typeof bypassParams === 'object') {
            bypassParams.admin = 'true';
            bypassParams.debug = 'true';
            bypassParams.test = 'true';
          }
          break;
        case 'path-traversal':
          // Try path traversal to access protected resource
          const protectedUrlObj = new URL(protectedUrl);
          const urlObj = new URL(url);
          urlObj.pathname = protectedUrlObj.pathname;
          bypassUrl = urlObj.toString();
          break;
        case 'method-manipulation':
          // Will be handled in the request interception
          break;
        default:
          // Use the provided URL as is
      }
      
      // Set up request interception to modify requests
      await page.setRequestInterception(true);
      
      page.on('request', request => {
        // Only intercept the specific request we're testing
        if (request.url().startsWith(url)) {
          const requestData = {
            method: bypassTechnique === 'method-manipulation' ? 
                    (method === 'GET' ? 'POST' : 'GET') : 
                    (method || 'GET'),
            headers: bypassHeaders
          };
          
          // Add post data if needed
          if (requestData.method === 'POST' && bypassParams) {
            requestData.postData = typeof bypassParams === 'string' ? 
                                  bypassParams : 
                                  JSON.stringify(bypassParams);
          }
          
          request.continue(requestData);
        } else {
          request.continue();
        }
      });
      
      // Navigate to the URL with bypass technique
      let response;
      if (method === 'GET' && bypassParams && typeof bypassParams === 'object') {
        // Add query parameters to URL
        const urlObj = new URL(bypassUrl);
        for (const [key, value] of Object.entries(bypassParams)) {
          urlObj.searchParams.append(key, value);
        }
        response = await page.goto(urlObj.toString(), {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      } else {
        response = await page.goto(bypassUrl, {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      }
      
      // Take a screenshot
      const screenshot = path.join(
        this.options.screenshotDirectory,
        `auth_bypass_verification_${Date.now()}.png`
      );
      
      await page.screenshot({
        path: screenshot,
        fullPage: true
      });
      
      // Check if we successfully accessed the protected content
      const responseText = await response.text();
      const pageContent = await page.content();
      
      // Check for evidence of successful bypass
      let bypassSuccessful = false;
      
      // Check if we're not on a login page
      const currentUrl = page.url();
      if (!currentUrl.includes('login') && !currentUrl.includes('signin') && !currentUrl.includes('auth')) {
        // Check for login forms
        const hasLoginForm = await page.evaluate(() => {
          const forms = Array.from(document.querySelectorAll('form'));
          return forms.some(form => {
            const formHtml = form.outerHTML.toLowerCase();
            return formHtml.includes('login') || 
                   formHtml.includes('signin') || 
                   formHtml.includes('username') || 
                   formHtml.includes('password');
          });
        });
        
        if (!hasLoginForm) {
          // Check response status
          if (response.status() !== 401 && response.status() !== 403) {
            bypassSuccessful = true;
          }
        }
      }
      
      // Check if evidence is present in response or page content
      let evidenceFound = false;
      if (evidence) {
        evidenceFound = responseText.includes(evidence) || pageContent.includes(evidence);
        if (evidenceFound) {
          bypassSuccessful = true;
        }
      }
      
      // Calculate confidence
      let confidence = 0;
      
      if (bypassSuccessful) {
        confidence = evidenceFound ? 1 : 0.8;
      }
      
      // Determine if finding is verified
      const verified = confidence >= this.options.verificationThreshold;
      
      // Close the page
      await page.close();
      
      return {
        verified,
        confidence,
        bypassSuccessful,
        bypassTechnique,
        evidenceFound,
        screenshot,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Error verifying authentication bypass:', error);
      
      return {
        verified: false,
        confidence: 0,
        error: error.message,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Verify access control finding
   * @param {Object} finding - Finding to verify
   * @param {Object} scannerConfig - Scanner configuration
   * @returns {Promise<Object>} - Verification result
   */
  async verifyAccessControl(finding, scannerConfig) {
    try {
      // Extract information from finding
      const { url, method, params, headers, payload, evidence, restrictedUrl, accessType } = finding;
      
      if (!url || !restrictedUrl) {
        return {
          verified: false,
          confidence: 0,
          reason: 'Missing URL or restricted URL in finding data',
          timestamp: Date.now()
        };
      }
      
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Set up request interception to modify requests
      await page.setRequestInterception(true);
      
      page.on('request', request => {
        // Only intercept the specific request we're testing
        if (request.url().startsWith(restrictedUrl)) {
          const requestData = {
            method: method || 'GET',
            headers: { ...request.headers(), ...headers }
          };
          
          // Add post data if method is POST
          if ((method === 'POST' || method === 'PUT') && params) {
            requestData.postData = typeof params === 'string' ? params : JSON.stringify(params);
          }
          
          request.continue(requestData);
        } else {
          request.continue();
        }
      });
      
      // Navigate to the restricted URL
      let response;
      if (method === 'GET' && params) {
        // Add query parameters to URL
        const urlObj = new URL(restrictedUrl);
        for (const [key, value] of Object.entries(params)) {
          urlObj.searchParams.append(key, value);
        }
        response = await page.goto(urlObj.toString(), {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      } else {
        response = await page.goto(restrictedUrl, {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      }
      
      // Take a screenshot
      const screenshot = path.join(
        this.options.screenshotDirectory,
        `access_control_verification_${Date.now()}.png`
      );
      
      await page.screenshot({
        path: screenshot,
        fullPage: true
      });
      
      // Check if we successfully accessed the restricted content
      const responseText = await response.text();
      const pageContent = await page.content();
      
      // Check for evidence of successful access
      let accessSuccessful = false;
      
      // Check response status
      if (response.status() === 200) {
        // Check if we were redirected to an error or login page
        const finalUrl = page.url();
        if (!finalUrl.includes('error') && 
            !finalUrl.includes('denied') && 
            !finalUrl.includes('login') && 
            !finalUrl.includes('signin')) {
          
          // Check for error messages in content
          const errorPatterns = [
            'access denied',
            'permission denied',
            'not authorized',
            'unauthorized',
            'forbidden',
            'not allowed',
            'login required',
            'sign in required'
          ];
          
          const hasErrorMessage = errorPatterns.some(pattern => 
            pageContent.toLowerCase().includes(pattern)
          );
          
          if (!hasErrorMessage) {
            accessSuccessful = true;
          }
        }
      }
      
      // Check if evidence is present in response or page content
      let evidenceFound = false;
      if (evidence) {
        evidenceFound = responseText.includes(evidence) || pageContent.includes(evidence);
        if (evidenceFound) {
          accessSuccessful = true;
        }
      }
      
      // Calculate confidence
      let confidence = 0;
      
      if (accessSuccessful) {
        confidence = evidenceFound ? 1 : 0.8;
      }
      
      // Determine if finding is verified
      const verified = confidence >= this.options.verificationThreshold;
      
      // Close the page
      await page.close();
      
      return {
        verified,
        confidence,
        accessSuccessful,
        accessType: accessType || 'unknown',
        evidenceFound,
        screenshot,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Error verifying access control:', error);
      
      return {
        verified: false,
        confidence: 0,
        error: error.message,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Verify generic finding
   * @param {Object} finding - Finding to verify
   * @param {Object} scannerConfig - Scanner configuration
   * @returns {Promise<Object>} - Verification result
   */
  async verifyGenericFinding(finding, scannerConfig) {
    try {
      // Extract information from finding
      const { url, method, params, headers, payload, evidence } = finding;
      
      if (!url) {
        return {
          verified: false,
          confidence: 0,
          reason: 'Missing URL in finding data',
          timestamp: Date.now()
        };
      }
      
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Set up request interception to modify requests
      await page.setRequestInterception(true);
      
      page.on('request', request => {
        // Only intercept the specific request we're testing
        if (request.url().startsWith(url) && request.method() === (method || 'GET')) {
          const requestData = {
            method: method || 'GET',
            headers: { ...request.headers(), ...headers }
          };
          
          // Add post data if method is POST
          if ((method === 'POST' || method === 'PUT') && params) {
            requestData.postData = typeof params === 'string' ? params : JSON.stringify(params);
          }
          
          request.continue(requestData);
        } else {
          request.continue();
        }
      });
      
      // Navigate to the URL
      let response;
      if (method === 'GET' && params) {
        // Add query parameters to URL
        const urlObj = new URL(url);
        for (const [key, value] of Object.entries(params)) {
          urlObj.searchParams.append(key, value);
        }
        response = await page.goto(urlObj.toString(), {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      } else {
        response = await page.goto(url, {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      }
      
      // Take a screenshot
      const screenshot = path.join(
        this.options.screenshotDirectory,
        `generic_verification_${Date.now()}.png`
      );
      
      await page.screenshot({
        path: screenshot,
        fullPage: true
      });
      
      // Check response for evidence
      const responseText = await response.text();
      const pageContent = await page.content();
      
      // Check if evidence is present in response or page content
      let evidenceFound = false;
      if (evidence) {
        evidenceFound = responseText.includes(evidence) || pageContent.includes(evidence);
      }
      
      // Calculate confidence based on evidence
      const confidence = evidenceFound ? 0.8 : 0.3;
      
      // Determine if finding is verified
      const verified = confidence >= this.options.verificationThreshold;
      
      // Close the page
      await page.close();
      
      return {
        verified,
        confidence,
        evidenceFound,
        screenshot,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Error verifying generic finding:', error);
      
      return {
        verified: false,
        confidence: 0,
        error: error.message,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Log verification result
   * @param {Object} finding - Finding
   * @param {Object} result - Verification result
   */
  logVerificationResult(finding, result) {
    try {
      if (!this.options.logResults) {
        return;
      }
      
      const logFile = path.join(
        this.options.logDirectory,
        `verification_${finding.id || Date.now()}.json`
      );
      
      const logData = {
        findingId: finding.id,
        findingType: finding.type,
        findingSeverity: finding.severity,
        verificationResult: result,
        timestamp: Date.now()
      };
      
      fs.writeFileSync(logFile, JSON.stringify(logData, null, 2));
    } catch (error) {
      console.error('Error logging verification result:', error);
    }
  }

  /**
   * Get verification results
   * @returns {Map} - Verification results
   */
  getVerificationResults() {
    return this.verificationResults;
  }

  /**
   * Get verification result for a finding
   * @param {string} findingId - Finding ID
   * @returns {Object} - Verification result
   */
  getVerificationResult(findingId) {
    return this.verificationResults.get(findingId);
  }

  /**
   * Clear verification results
   */
  clearVerificationResults() {
    this.verificationResults.clear();
    
    this.emit('resultsCleared');
  }

  /**
   * Set verification threshold
   * @param {number} threshold - Verification threshold
   */
  setVerificationThreshold(threshold) {
    this.options.verificationThreshold = threshold;
    
    this.emit('configChanged', {
      option: 'verificationThreshold',
      value: threshold
    });
  }

  /**
   * Close the finding verification system
   * @returns {Promise<void>}
   */
  async close() {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      
      this.emit('closed');
    }
  }
}

module.exports = FindingVerificationSystem;

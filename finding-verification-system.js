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
            // Check for hidden input fields th
(Content truncated due to size limit. Use line ranges to read in chunks)
/**
 * CSRF Token Validation Scanner Module
 * 
 * This module detects Cross-Site Request Forgery (CSRF) vulnerabilities
 * by analyzing forms and requests for proper CSRF protection mechanisms.
 */

const axios = require('axios');
const { URL } = require('url');
const { generateCsrfPayloads } = require('../utils/payload-generator');
const { analyzeResponse } = require('../utils/response-analyzer');
const puppeteer = require('puppeteer');

class CsrfScanner {
  constructor() {
    this.name = 'csrf-scanner';
    this.description = 'Detects Cross-Site Request Forgery (CSRF) vulnerabilities';
    this.payloads = generateCsrfPayloads();
  }

  /**
   * Scan target for CSRF vulnerabilities
   * @param {Object} target - Target information
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async scan(target, options) {
    const findings = [];
    const targetUrl = target.url;
    
    try {
      // Launch headless browser for form analysis
      const browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
      
      const page = await browser.newPage();
      await page.setUserAgent(options.userAgent);
      
      // Navigate to the target URL
      await page.goto(targetUrl, { 
        waitUntil: 'networkidle2', 
        timeout: options.timeout 
      });
      
      // Find all forms on the page
      const forms = await page.evaluate(() => {
        const formElements = Array.from(document.querySelectorAll('form'));
        return formElements.map(form => {
          // Get form attributes
          const action = form.action;
          const method = form.method.toUpperCase() || 'GET';
          
          // Get form inputs
          const inputs = Array.from(form.querySelectorAll('input, select, textarea'))
            .map(input => {
              return {
                name: input.name,
                type: input.type,
                value: input.value,
                id: input.id
              };
            });
          
          return { action, method, inputs };
        });
      });
      
      // Check each form for CSRF protection
      for (let i = 0; i < forms.length; i++) {
        const form = forms[i];
        
        // Skip GET forms as they are not typically vulnerable to CSRF
        if (form.method === 'GET') {
          continue;
        }
        
        // Check for CSRF token in form inputs
        const hasCsrfToken = this.checkForCsrfToken(form.inputs);
        
        if (!hasCsrfToken) {
          // Check if the form submission is protected by other means
          const isProtected = await this.checkFormProtection(page, i, options);
          
          if (!isProtected) {
            findings.push({
              type: 'csrf-vulnerability',
              severity: 'medium',
              confidence: 'medium',
              form: i,
              url: targetUrl,
              formAction: form.action,
              formMethod: form.method,
              evidence: JSON.stringify(form),
              description: `Form #${i+1} (${form.action}) lacks CSRF protection`,
              remediation: 'Implement CSRF tokens for all state-changing operations. Use SameSite cookie attribute and consider implementing additional protections like custom request headers.',
              cvss: 5.8,
              cwe: 'CWE-352'
            });
          }
        }
      }
      
      // Check for CSRF protection in API endpoints
      if (target.api && target.api.endpoints) {
        for (const endpoint of target.api.endpoints) {
          if (endpoint.method !== 'GET') {
            const isProtected = await this.checkApiEndpointProtection(endpoint, options);
            
            if (!isProtected) {
              findings.push({
                type: 'csrf-vulnerability',
                severity: 'medium',
                confidence: 'medium',
                endpoint: endpoint.path,
                method: endpoint.method,
                url: endpoint.url || targetUrl + endpoint.path,
                evidence: JSON.stringify(endpoint),
                description: `API endpoint ${endpoint.method} ${endpoint.path} lacks CSRF protection`,
                remediation: 'Implement CSRF tokens or custom request headers for API endpoints. Use SameSite cookie attribute and consider implementing additional protections.',
                cvss: 6.5,
                cwe: 'CWE-352'
              });
            }
          }
        }
      }
      
      // Check for SameSite cookie attribute
      const cookies = await page.cookies();
      for (const cookie of cookies) {
        if ((cookie.name.toLowerCase().includes('session') || 
             cookie.name.toLowerCase().includes('auth') || 
             cookie.name.toLowerCase().includes('token')) && 
            (!cookie.sameSite || cookie.sameSite === 'None')) {
          findings.push({
            type: 'missing-samesite',
            severity: 'low',
            confidence: 'high',
            cookie: cookie.name,
            url: targetUrl,
            evidence: JSON.stringify(cookie),
            description: `Cookie '${cookie.name}' is missing SameSite attribute or set to 'None'`,
            remediation: 'Set SameSite attribute to "Lax" or "Strict" for authentication and session cookies.',
            cvss: 3.8,
            cwe: 'CWE-1275'
          });
        }
      }
      
      await browser.close();
      
      return findings;
    } catch (error) {
      console.error(`Error in CSRF scan: ${error.message}`);
      return findings;
    }
  }

  /**
   * Check if form inputs contain a CSRF token
   * @param {Array} inputs - Form input elements
   * @returns {boolean} - True if CSRF token is present, false otherwise
   */
  checkForCsrfToken(inputs) {
    const csrfTokenPatterns = [
      'csrf',
      'xsrf',
      'token',
      '_token',
      'authenticity_token',
      'csrf_token',
      'xsrf_token',
      'anti_csrf',
      'anti-csrf',
      'csrf-protection',
      'csrf_protection'
    ];
    
    for (const input of inputs) {
      const inputName = (input.name || '').toLowerCase();
      const inputId = (input.id || '').toLowerCase();
      
      for (const pattern of csrfTokenPatterns) {
        if (inputName.includes(pattern) || inputId.includes(pattern)) {
          return true;
        }
      }
    }
    
    return false;
  }

  /**
   * Check if a form is protected against CSRF by other means
   * @param {Object} page - Puppeteer page object
   * @param {number} formIndex - Index of the form to check
   * @param {Object} options - Scanner options
   * @returns {boolean} - True if form is protected, false otherwise
   */
  async checkFormProtection(page, formIndex, options) {
    try {
      // Check for custom headers in form submission
      const requestHeaders = {};
      
      await page.setRequestInterception(true);
      
      const interceptPromise = new Promise(resolve => {
        page.once('request', request => {
          const headers = request.headers();
          request.continue();
          resolve(headers);
        });
      });
      
      // Submit the form
      await page.evaluate((formIndex) => {
        const forms = document.querySelectorAll('form');
        if (forms[formIndex]) {
          // Prevent actual form submission by setting a dummy action
          const originalAction = forms[formIndex].action;
          forms[formIndex].action = 'javascript:void(0)';
          forms[formIndex].submit();
          forms[formIndex].action = originalAction;
        }
      }, formIndex);
      
      const headers = await interceptPromise;
      
      await page.setRequestInterception(false);
      
      // Check for custom headers that might be used for CSRF protection
      const csrfHeaderPatterns = [
        'x-csrf-token',
        'x-xsrf-token',
        'x-requested-with'
      ];
      
      for (const pattern of csrfHeaderPatterns) {
        if (headers[pattern]) {
          return true;
        }
      }
      
      // Check if the Origin or Referer header is validated by the server
      // This would require sending multiple requests with different headers
      // and comparing responses, which is complex for this implementation
      
      return false;
    } catch (error) {
      console.error(`Error checking form protection: ${error.message}`);
      return false;
    }
  }

  /**
   * Check if an API endpoint is protected against CSRF
   * @param {Object} endpoint - API endpoint information
   * @param {Object} options - Scanner options
   * @returns {boolean} - True if endpoint is protected, false otherwise
   */
  async checkApiEndpointProtection(endpoint, options) {
    try {
      // Make a request to the endpoint
      const response = await axios({
        method: endpoint.method,
        url: endpoint.url,
        headers: {
          'User-Agent': options.userAgent,
          'Content-Type': 'application/json'
        },
        timeout: options.timeout,
        validateStatus: () => true
      });
      
      // Check response headers for CSRF protection indicators
      const headers = response.headers;
      
      const csrfHeaderPatterns = [
        'x-csrf-token',
        'csrf-token',
        'x-xsrf-token',
        'xsrf-token'
      ];
      
      for (const pattern of csrfHeaderPatterns) {
        if (headers[pattern]) {
          return true;
        }
      }
      
      // Check if the endpoint requires a custom header
      // This would require sending multiple requests with different headers
      // and comparing responses, which is complex for this implementation
      
      return false;
    } catch (error) {
      console.error(`Error checking API endpoint protection: ${error.message}`);
      return false;
    }
  }
}

module.exports = CsrfScanner;

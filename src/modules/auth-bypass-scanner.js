/**
 * Authentication Bypass Scanner Module
 * 
 * This module detects authentication bypass vulnerabilities by testing
 * various techniques to bypass authentication mechanisms.
 */

const axios = require('axios');
const { URL } = require('url');
const { generateAuthBypassPayloads } = require('../utils/payload-generator');
const { analyzeResponse } = require('../utils/response-analyzer');
const puppeteer = require('puppeteer');

class AuthBypassScanner {
  constructor() {
    this.name = 'auth-bypass-scanner';
    this.description = 'Detects authentication bypass vulnerabilities';
    this.payloads = generateAuthBypassPayloads();
  }

  /**
   * Scan target for authentication bypass vulnerabilities
   * @param {Object} target - Target information
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async scan(target, options) {
    const findings = [];
    const targetUrl = target.url;
    
    try {
      // Identify authentication endpoints
      const authEndpoints = await this.identifyAuthEndpoints(target, options);
      
      // Test SQL injection based authentication bypass
      const sqlInjectionFindings = await this.testSqlInjectionBypass(authEndpoints, options);
      findings.push(...sqlInjectionFindings);
      
      // Test default credentials
      const defaultCredFindings = await this.testDefaultCredentials(authEndpoints, options);
      findings.push(...defaultCredFindings);
      
      // Test authentication logic flaws
      const logicFlawFindings = await this.testAuthLogicFlaws(authEndpoints, options);
      findings.push(...logicFlawFindings);
      
      // Test JWT token tampering
      const jwtTamperingFindings = await this.testJwtTampering(target, options);
      findings.push(...jwtTamperingFindings);
      
      // Test cookie manipulation
      const cookieManipulationFindings = await this.testCookieManipulation(target, options);
      findings.push(...cookieManipulationFindings);
      
      return findings;
    } catch (error) {
      console.error(`Error in authentication bypass scan: ${error.message}`);
      return findings;
    }
  }

  /**
   * Identify authentication endpoints
   * @param {Object} target - Target information
   * @param {Object} options - Scanner options
   * @returns {Array} - List of authentication endpoints
   */
  async identifyAuthEndpoints(target, options) {
    const endpoints = [];
    
    // If target has authentication endpoints defined, use those
    if (target.auth && target.auth.endpoints) {
      return target.auth.endpoints;
    }
    
    // Otherwise, try to identify common authentication endpoints
    const commonAuthPaths = [
      '/login',
      '/signin',
      '/auth',
      '/authenticate',
      '/account/login',
      '/user/login',
      '/admin/login',
      '/api/login',
      '/api/auth',
      '/api/authenticate',
      '/api/token',
      '/api/session'
    ];
    
    // Try to detect login forms using headless browser
    try {
      const browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
      
      const page = await browser.newPage();
      await page.setUserAgent(options.userAgent);
      
      // Check the main page for login forms
      await page.goto(target.url, { 
        waitUntil: 'networkidle2', 
        timeout: options.timeout 
      });
      
      const loginForms = await page.evaluate(() => {
        const forms = Array.from(document.querySelectorAll('form'));
        return forms
          .filter(form => {
            const formHTML = form.outerHTML.toLowerCase();
            const hasPasswordField = form.querySelector('input[type="password"]') !== null;
            const isLoginForm = 
              formHTML.includes('login') || 
              formHTML.includes('signin') || 
              formHTML.includes('log in') || 
              formHTML.includes('sign in') || 
              formHTML.includes('auth');
            
            return hasPasswordField || isLoginForm;
          })
          .map(form => {
            return {
              action: form.action,
              method: form.method.toUpperCase() || 'GET',
              inputs: Array.from(form.querySelectorAll('input')).map(input => {
                return {
                  name: input.name,
                  type: input.type,
                  id: input.id
                };
              })
            };
          });
      });
      
      // Add detected login forms to endpoints
      for (const form of loginForms) {
        endpoints.push({
          url: form.action || target.url,
          method: form.method,
          type: 'form',
          inputs: form.inputs
        });
      }
      
      // Check common auth paths
      for (const path of commonAuthPaths) {
        try {
          const url = new URL(path, target.url).toString();
          await page.goto(url, { 
            waitUntil: 'networkidle2', 
            timeout: options.timeout / 2 // Use shorter timeout for these checks
          });
          
          // Check if the page has a login form
          const hasLoginForm = await page.evaluate(() => {
            return document.querySelector('input[type="password"]') !== null;
          });
          
          if (hasLoginForm) {
            const forms = await page.evaluate(() => {
              const forms = Array.from(document.querySelectorAll('form'));
              return forms.map(form => {
                return {
                  action: form.action,
                  method: form.method.toUpperCase() || 'GET',
                  inputs: Array.from(form.querySelectorAll('input')).map(input => {
                    return {
                      name: input.name,
                      type: input.type,
                      id: input.id
                    };
                  })
                };
              });
            });
            
            for (const form of forms) {
              endpoints.push({
                url: form.action || url,
                method: form.method,
                type: 'form',
                inputs: form.inputs
              });
            }
          }
        } catch (error) {
          // Ignore errors for individual path checks
        }
      }
      
      await browser.close();
    } catch (error) {
      console.error(`Error detecting login forms: ${error.message}`);
    }
    
    // Add common API auth endpoints
    for (const path of commonAuthPaths) {
      if (path.startsWith('/api/')) {
        endpoints.push({
          url: new URL(path, target.url).toString(),
          method: 'POST',
          type: 'api',
          contentType: 'application/json'
        });
      }
    }
    
    return endpoints;
  }

  /**
   * Test SQL injection based authentication bypass
   * @param {Array} authEndpoints - Authentication endpoints to test
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async testSqlInjectionBypass(authEndpoints, options) {
    const findings = [];
    
    // Get SQL injection payloads for auth bypass
    const sqlInjectionPayloads = this.payloads.filter(p => 
      p.includes("'") || 
      p.includes("--") || 
      p.includes("#") || 
      p.includes("/*")
    );
    
    for (const endpoint of authEndpoints) {
      if (endpoint.type === 'form') {
        // Find username and password fields
        const usernameField = endpoint.inputs.find(input => 
          input.type === 'text' || 
          input.type === 'email' || 
          input.name.toLowerCase().includes('user') || 
          input.name.toLowerCase().includes('email') || 
          input.name.toLowerCase().includes('login') || 
          input.id.toLowerCase().includes('user') || 
          input.id.toLowerCase().includes('email') || 
          input.id.toLowerCase().includes('login')
        );
        
        const passwordField = endpoint.inputs.find(input => 
          input.type === 'password' || 
          input.name.toLowerCase().includes('pass') || 
          input.id.toLowerCase().includes('pass')
        );
        
        if (usernameField && passwordField) {
          for (const payload of sqlInjectionPayloads) {
            try {
              // Create form data
              const formData = new URLSearchParams();
              formData.append(usernameField.name, payload);
              formData.append(passwordField.name, 'password');
              
              // Add other form fields with default values
              for (const input of endpoint.inputs) {
                if (input.name && 
                    input.name !== usernameField.name && 
                    input.name !== passwordField.name) {
                  formData.append(input.name, input.type === 'checkbox' ? 'on' : 'default');
                }
              }
              
              // Send the request
              const response = await axios({
                method: endpoint.method,
                url: endpoint.url,
                data: formData.toString(),
                headers: {
                  'User-Agent': options.userAgent,
                  'Content-Type': 'application/x-www-form-urlencoded'
                },
                timeout: options.timeout,
                validateStatus: () => true, // Accept any status code
                maxRedirects: options.followRedirects ? 5 : 0
              });
              
              // Check if authentication was bypassed
              const isVulnerable = this.checkAuthBypassSuccess(response);
              
              if (isVulnerable) {
                findings.push({
                  type: 'sql-injection-auth-bypass',
                  severity: 'critical',
                  confidence: 'medium',
                  endpoint: endpoint.url,
                  method: endpoint.method,
                  field: usernameField.name,
                  payload: payload,
                  evidence: this.extractEvidence(response),
                  description: `SQL injection authentication bypass vulnerability detected in login form at ${endpoint.url}`,
                  remediation: 'Use parameterized queries or prepared statements for authentication. Implement proper input validation and sanitization.',
                  cvss: 9.8,
                  cwe: 'CWE-89'
                });
                
                // Break the payload loop for this endpoint once we find a vulnerability
                break;
              }
            } catch (error) {
              console.error(`Error testing SQL injection auth bypass: ${error.message}`);
              // Continue with the next payload
            }
          }
        }
      } else if (endpoint.type === 'api') {
        for (const payload of sqlInjectionPayloads) {
          try {
            // Create JSON data for API
            const jsonData = {
              username: payload,
              password: 'password'
            };
            
            // Send the request
            const response = await axios({
              method: endpoint.method,
              url: endpoint.url,
              data: jsonData,
              headers: {
                'User-Agent': options.userAgent,
                'Content-Type': endpoint.contentType || 'application/json'
              },
              timeout: options.timeout,
              validateStatus: () => true, // Accept any status code
              maxRedirects: options.followRedirects ? 5 : 0
            });
            
            // Check if authentication was bypassed
            const isVulnerable = this.checkAuthBypassSuccess(response);
            
            if (isVulnerable) {
              findings.push({
                type: 'sql-injection-auth-bypass',
                severity: 'critical',
                confidence: 'medium',
                endpoint: endpoint.url,
                method: endpoint.method,
                field: 'username',
                payload: payload,
                evidence: this.extractEvidence(response),
                description: `SQL injection authentication bypass vulnerability detected in API endpoint ${endpoint.url}`,
                remediation: 'Use parameterized queries or prepared statements for authentication. Implement proper input validation and sanitization.',
                cvss: 9.8,
                cwe: 'CWE-89'
              });
              
              // Break the payload loop for this endpoint once we find a vulnerability
              break;
            }
          } catch (error) {
            console.error(`Error testing SQL injection auth bypass: ${error.message}`);
            // Continue with the next payload
          }
        }
      }
    }
    
    return findings;
  }

  /**
   * Test default credentials
   * @param {Array} authEndpoints - Authentication endpoints to test
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async testDefaultCredentials(authEndpoints, options) {
    const findings = [];
    
    // Get default credentials payloads
    const defaultCredentials = [
      { username: 'admin', password: 'admin' },
      { username: 'admin', password: 'password' },
      { username: 'admin', password: '123456' },
      { username: 'admin', password: 'admin123' },
      { username: 'root', password: 'root' },
      { username: 'root', password: 'toor' },
      { username: 'administrator', password: 'administrator' },
      { username: 'administrator', password: 'password' },
      { username: 'user', password: 'user' },
      { username: 'user', password: 'password' },
      { username: 'test', password: 'test' },
      { username: 'guest', password: 'guest' }
    ];
    
    for (const endpoint of authEndpoints) {
      if (endpoint.type === 'form') {
        // Find username and password fields
        const usernameField = endpoint.inputs.find(input => 
          input.type === 'text' || 
          input.type === 'email' || 
          input.name.toLowerCase().includes('user') || 
          input.name.toLowerCase().includes('email') || 
          input.name.toLowerCase().includes('login') || 
          input.id.toLowerCase().includes('user') || 
          input.id.toLowerCase().includes('email') || 
          input.id.toLowerCase().includes('login')
        );
        
        const passwordField = endpoint.inputs.find(input => 
          input.type === 'password' || 
          input.name.toLowerCase().includes('pass') || 
          input.id.toLowerCase().includes('pass')
        );
        
        if (usernameField && passwordField) {
          for (const cred of defaultCredentials) {
            try {
              // Create form data
              const formData = new URLSearchParams();
              formData.append(usernameField.name, cred.username);
              formData.append(passwordField.name, cred.password);
              
              // Add other form fields with default values
              for (const input of endpoint.inputs) {
                if (input.name && 
                    input.name !== usernameField.name && 
                    input.name !== passwordField.name) {
                  formData.append(input.name, input.type === 'checkbox' ? 'on' : 'default');
                }
              }
              
              // Send the request
              const response = await axios({
                method: endpoint.method,
                url: endpoint.url,
                data: formData.toString(),
                headers: {
                  'User-Agent': options.userAgent,
                  'Content-Type': 'application/x-www-form-urlencoded'
                },
                timeout: options.timeout,
                validateStatus: () => true, // Accept any status code
                maxRedirects: options.followRedirects ? 5 : 0
              });
              
              // Check if authentication was successful
              const isVulnerable = this.checkAuthBypassSuccess(response);
              
              if (isVulnerable) {
                findings.push({
                  type: 'default-credentials',
                  severity: 'high',
                  confidence: 'high',
                  endpoint: endpoint.url,
                  method: endpoint.method,
                  credentials: `${cred.username}:${cred.password}`,
                  evidence: this.extractEvidence(response),
                  description: `Default credentials (${cred.username}:${cred.password}) work at ${endpoint.url}`,
                  remediation: 'Change default credentials and implement strong password policies. Consider implementing account lockout after multiple failed attempts.',
                  cvss: 7.5,
                  cwe: 'CWE-521'
                });
                
                // Break the credentials loop for this endpoint once we find a vulnerability
                break;
              }
            } catch (error) {
              console.error(`Error testing default credentials: ${error.message}`);
              // Continue with the next credential
            }
          }
        }
      } else if (endpoint.type === 'api') {
        for (const cred of defaultCredentials) {
          try {
            // Create JSON data for API
            const jsonData = {
              username: cred.username,
              password: cred.password
            };
            
            // Send the request
            const response = await axios({
              method: endpoint.method,
              url: endpoint.url,
              data: jsonData,
              headers: {
                'User-Agent': options.userAgent,
                'Content-Type': endpoint.contentType || 'application/json'
              },
              timeout: options.timeout,
              validateStatus: () => true, // Accept any status code
              maxRedirects: options.followRedirects ? 5 : 0
            });
            
            // Check if authentication was successful
            const isVulnerable = this.checkAuthBypassSuccess(response);
            
            if (isVulnerable) {
              findings.push({
                type: 'default-credentials',
                severity: 'high',
                confidence: 'high',
                endpoint: endpoint.url,
                method: endpoint.method,
                credentials: `${cred.username}:${cred.password}`,
                evidence: this.extractEvidence(response),
                description: `Default credentials (${cred.username}:${cred.password}) work at API endpoint ${endpoint.url}`,
                remediation: 'Change default credentials and implement strong password policies. Consider implementing account lockout after multiple failed attempts.',
                cvss: 7.5,
                cwe: 'CWE-521'
              });
              
              // Break the credentials loop for this endpoint once we find a vulnerability
              break;
            }
          } catch (error) {
            console.error(`Error testing default credentials: ${error.message}`);
            // Continue with the next credential
          }
        }
      }
    }
    
    return findings;
  }

  /**
   * Test authentication logic flaws
   * @param {Array} authEndpoints - Authentication endpoints to test
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async testAuthLogicFlaws(authEndpoints, options) {
    const findings = [];
    
    // Test for various authentication logic flaws
    for (const endpoint of authEndpoints) {
      // Test for username enumeration
      const usernameEnumerationFindings = await this.testUsernameEnumeration(endpoint, options);
      findings.push(...usernameEnumerationFindings);
      
      // Test for lack of account lockout
      const accountLockoutFindings = await this.testAccountLockout(endpoint, options);
      findings.push(...accountLockoutFindings);
      
      // Test for password reset flaws
      // This is complex and would require more context about the application
      // Skipping for this implementation
    }
    
    return findings;
  }

  /**
   * Test for username enumeration vulnerability
   * @param {Object} endpoint - Authentication endpoint to test
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async testUsernameEnumeration(endpoint, options) {
    const findings = [];
    
    if (endpoint.type === 'form') {
      // Find username and password fields
      const usernameField = endpoint.inputs.find(input => 
        input.type === 'text' || 
        input.type === 'email' || 
        input.name.toLowerCase().includes('user') || 
        input.name.toLowerCase().includes('email') || 
        input.name.toLowerCase().includes('login') || 
        input.id.toLowerCase().includes('user') || 
        input.id.toLowerCase().includes('email') || 
        input.id.toLowerCase().includes('login')
      );
      
      const passwordField = endpoint.inputs.find(input => 
        input.type === 'password' || 
        input.name.toLowerCase().includes('pass') || 
        input.id.toLowerCase().includes('pass')
      );
      
      if (usernameField && passwordField) {
        try {
          // Test with a likely valid username and invalid password
          const validFormData = new URLSearchParams();
          validFormData.append(usernameField.name, 'admin');
          validFormData.append(passwordField.name, 'invalidpassword123');
          
          // Add other form fields with default values
          for (const input of endpoint.inputs) {
            if (input.name && 
                input.name !== usernameField.name && 
                input.name !== passwordField.name) {
              validFormData.append(input.name, input.type === 'checkbox' ? 'on' : 'default');
            }
          }
          
          const validResponse = await axios({
            method: endpoint.method,
            url: endpoint.url,
            data: validFormData.toString(),
            headers: {
              'User-Agent': options.userAgent,
              'Content-Type': 'application/x-www-form-urlencoded'
            },
            timeout: options.timeout,
            validateStatus: () => true,
            maxRedirects: options.followRedirects ? 5 : 0
          });
          
          // Test with a likely invalid username and invalid password
          const invalidFormData = new URLSearchParams();
          invalidFormData.append(usernameField.name, 'nonexistentuser123456789');
          invalidFormData.append(passwordField.name, 'invalidpassword123');
          
          // Add other form fields with default values
          for (const input of endpoint.inputs) {
            if (input.name && 
                input.name !== usernameField.name && 
                input.name !== passwordField.name) {
              invalidFormData.append(input.name, input.type === 'checkbox' ? 'on' : 'default');
            }
          }
          
          const invalidResponse = await axios({
            method: endpoint.method,
            url: endpoint.url,
            data: invalidFormData.toString(),
            headers: {
              'User-Agent': options.userAgent,
              'Content-Type': 'application/x-www-form-urlencoded'
            },
            timeout: options.timeout,
            validateStatus: () => true,
            maxRedirects: options.followRedirects ? 5 : 0
          });
          
          // Compare responses to detect username enumeration
          const isVulnerable = this.detectUsernameEnumeration(validResponse, invalidResponse);
          
          if (isVulnerable) {
            findings.push({
              type: 'username-enumeration',
              severity: 'medium',
              confidence: 'medium',
              endpoint: endpoint.url,
              method: endpoint.method,
              evidence: `Different responses for valid vs. invalid usernames`,
              description: `Username enumeration vulnerability detected at ${endpoint.url}`,
              remediation: 'Use generic error messages that do not reveal whether the username or password was incorrect. Implement consistent response times.',
              cvss: 5.3,
              cwe: 'CWE-203'
            });
          }
        } catch (error) {
          console.error(`Error testing username enumeration: ${error.message}`);
        }
      }
    }
    
    return findings;
  }

  /**
   * Test for lack of account lockout
   * @param {Object} endpoint - Authentication endpoint to test
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async testAccountLockout(endpoint, options) {
    const findings = [];
    
    if (endpoint.type === 'form') {
      // Find username and password fields
      const usernameField = endpoint.inputs.find(input => 
        input.type === 'text' || 
        input.type === 'email' || 
        input.name.toLowerCase().includes('user') || 
        input.name.toLowerCase().includes('email') || 
        input.name.toLowerCase().includes('login') || 
        input.id.toLowerCase().includes('user') || 
        input.id.toLowerCase().includes('email') || 
        input.id.toLowerCase().includes('login')
      );
      
      const passwordField = endpoint.inputs.find(input => 
        input.type === 'password' || 
        input.name.toLowerCase().includes('pass') || 
        input.id.toLowerCase().includes('pass')
      );
      
      if (usernameField && passwordField) {
        try {
          // Try multiple login attempts with the same username
          const username = 'admin';
          const attempts = 5; // Number of attempts to try
          let allResponsesSuccessful = true;
          
          for (let i = 0; i < attempts; i++) {
            // Create form data
            const formData = new URLSearchParams();
            formData.append(usernameField.name, username);
            formData.append(passwordField.name, `invalidpassword${i}`);
            
            // Add other form fields with default values
            for (const input of endpoint.inputs) {
              if (input.name && 
                  input.name !== usernameField.name && 
                  input.name !== passwordField.name) {
                formData.append(input.name, input.type === 'checkbox' ? 'on' : 'default');
              }
            }
            
            const response = await axios({
              method: endpoint.method,
              url: endpoint.url,
              data: formData.toString(),
              headers: {
                'User-Agent': options.userAgent,
                'Content-Type': 'application/x-www-form-urlencoded'
              },
              timeout: options.timeout,
              validateStatus: () => true,
              maxRedirects: options.followRedirects ? 5 : 0
            });
            
            // Check if the response indicates a lockout
            if (response.status === 429 || 
                (response.data && typeof response.data === 'string' && 
                 (response.data.includes('locked') || 
                  response.data.includes('too many attempts') || 
                  response.data.includes('try again later')))) {
              allResponsesSuccessful = false;
              break;
            }
          }
          
          if (allResponsesSuccessful) {
            findings.push({
              type: 'missing-account-lockout',
              severity: 'medium',
              confidence: 'medium',
              endpoint: endpoint.url,
              method: endpoint.method,
              evidence: `${attempts} failed login attempts were allowed without lockout`,
              description: `Missing account lockout mechanism detected at ${endpoint.url}`,
              remediation: 'Implement account lockout after a certain number of failed login attempts. Consider using exponential backoff for retry attempts.',
              cvss: 5.0,
              cwe: 'CWE-307'
            });
          }
        } catch (error) {
          console.error(`Error testing account lockout: ${error.message}`);
        }
      }
    }
    
    return findings;
  }

  /**
   * Test JWT token tampering
   * @param {Object} target - Target information
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async testJwtTampering(target, options) {
    const findings = [];
    
    try {
      // First, check if the application uses JWT
      const response = await axios.get(target.url, {
        timeout: options.timeout,
        headers: {
          'User-Agent': options.userAgent
        },
        validateStatus: () => true,
        maxRedirects: options.followRedirects ? 5 : 0
      });
      
      // Extract JWT tokens from response
      const jwtTokens = this.extractJwtTokens(response);
      
      if (jwtTokens.length > 0) {
        // Test for "none" algorithm vulnerability
        for (const token of jwtTokens) {
          const parts = token.split('.');
          if (parts.length === 3) {
            try {
              // Decode header
              const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
              
              // Create a "none" algorithm token
              const noneHeader = { ...header, alg: 'none' };
              const noneHeaderBase64 = Buffer.from(JSON.stringify(noneHeader)).toString('base64').replace(/=/g, '');
              
              // Decode payload
              const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
              
              // Modify payload to claim admin privileges
              const modifiedPayload = { ...payload, admin: true, role: 'admin' };
              const modifiedPayloadBase64 = Buffer.from(JSON.stringify(modifiedPayload)).toString('base64').replace(/=/g, '');
              
              // Create tampered token
              const tamperedToken = `${noneHeaderBase64}.${modifiedPayloadBase64}.`;
              
              // Test the tampered token
              const tamperedResponse = await axios.get(target.url, {
                timeout: options.timeout,
                headers: {
                  'User-Agent': options.userAgent,
                  'Authorization': `Bearer ${tamperedToken}`,
                  'Cookie': response.headers['set-cookie'] ? 
                    response.headers['set-cookie'].map(cookie => cookie.split(';')[0]).join('; ').replace(token, tamperedToken) : 
                    ''
                },
                validateStatus: () => true,
                maxRedirects: options.followRedirects ? 5 : 0
              });
              
              // Check if the tampered token was accepted
              const isVulnerable = this.checkAuthBypassSuccess(tamperedResponse);
              
              if (isVulnerable) {
                findings.push({
                  type: 'jwt-none-algorithm',
                  severity: 'critical',
                  confidence: 'medium',
                  token: tamperedToken,
                  evidence: this.extractEvidence(tamperedResponse),
                  description: 'JWT token "none" algorithm vulnerability detected',
                  remediation: 'Validate the algorithm used in JWT tokens and reject tokens with "none" algorithm. Use a strong secret key for token signing.',
                  cvss: 9.8,
                  cwe: 'CWE-347'
                });
              }
            } catch (error) {
              console.error(`Error testing JWT token: ${error.message}`);
            }
          }
        }
      }
    } catch (error) {
      console.error(`Error in JWT tampering test: ${error.message}`);
    }
    
    return findings;
  }

  /**
   * Test cookie manipulation
   * @param {Object} target - Target information
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async testCookieManipulation(target, options) {
    const findings = [];
    
    try {
      // First, get cookies from the application
      const response = await axios.get(target.url, {
        timeout: options.timeout,
        headers: {
          'User-Agent': options.userAgent
        },
        validateStatus: () => true,
        maxRedirects: options.followRedirects ? 5 : 0
      });
      
      if (response.headers['set-cookie']) {
        const cookies = Array.isArray(response.headers['set-cookie']) ? 
          response.headers['set-cookie'] : 
          [response.headers['set-cookie']];
        
        // Test each cookie for manipulation
        for (const cookie of cookies) {
          const cookieName = cookie.split('=')[0];
          const cookieValue = cookie.split('=')[1].split(';')[0];
          
          // Skip session cookies for now
          if (cookieName.toLowerCase().includes('session') || 
              cookieName.toLowerCase().includes('token') || 
              cookieName.toLowerCase().includes('jwt')) {
            continue;
          }
          
          // Test for role/privilege manipulation
          const roleValues = ['admin', 'administrator', 'true', '1', 'yes'];
          
          for (const roleValue of roleValues) {
            // Create manipulated cookie
            const manipulatedCookie = `${cookieName}=${roleValue}`;
            
            // Test the manipulated cookie
            const tamperedResponse = await axios.get(target.url, {
              timeout: options.timeout,
              headers: {
                'User-Agent': options.userAgent,
                'Cookie': manipulatedCookie
              },
              validateStatus: () => true,
              maxRedirects: options.followRedirects ? 5 : 0
            });
            
            // Check if the manipulated cookie was accepted
            const isVulnerable = this.checkAuthBypassSuccess(tamperedResponse);
            
            if (isVulnerable) {
              findings.push({
                type: 'cookie-manipulation',
                severity: 'high',
                confidence: 'medium',
                cookie: manipulatedCookie,
                evidence: this.extractEvidence(tamperedResponse),
                description: `Cookie manipulation vulnerability detected with cookie: ${manipulatedCookie}`,
                remediation: 'Use signed or encrypted cookies for storing sensitive information. Validate cookie values server-side and do not trust client-provided values for authorization decisions.',
                cvss: 8.0,
                cwe: 'CWE-565'
              });
              
              // Break the role value loop for this cookie once we find a vulnerability
              break;
            }
          }
        }
      }
    } catch (error) {
      console.error(`Error in cookie manipulation test: ${error.message}`);
    }
    
    return findings;
  }

  /**
   * Check if authentication bypass was successful
   * @param {Object} response - Axios response object
   * @returns {boolean} - True if authentication was bypassed, false otherwise
   */
  checkAuthBypassSuccess(response) {
    const { data, status, headers } = response;
    const responseText = typeof data === 'string' ? data : JSON.stringify(data);
    
    // Check for successful authentication indicators in response
    const authSuccessPatterns = [
      'admin',
      'dashboard',
      'welcome',
      'logged in',
      'sign out',
      'logout',
      'profile',
      'account',
      'settings',
      'administration',
      'successfully authenticated',
      'authentication successful',
      'login successful',
      'you are now logged in'
    ];
    
    for (const pattern of authSuccessPatterns) {
      if (responseText.toLowerCase().includes(pattern.toLowerCase())) {
        return true;
      }
    }
    
    // Check for authentication cookies or tokens in headers
    if (headers['set-cookie']) {
      const cookies = Array.isArray(headers['set-cookie']) ? 
        headers['set-cookie'] : 
        [headers['set-cookie']];
      
      for (const cookie of cookies) {
        if (cookie.toLowerCase().includes('auth') || 
            cookie.toLowerCase().includes('session') || 
            cookie.toLowerCase().includes('token') || 
            cookie.toLowerCase().includes('user') || 
            cookie.toLowerCase().includes('admin') || 
            cookie.toLowerCase().includes('logged')) {
          return true;
        }
      }
    }
    
    // Check for JWT tokens in response
    const jwtPattern = /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;
    if (responseText.match(jwtPattern)) {
      return true;
    }
    
    // Check for redirect to authenticated area
    if ((status === 302 || status === 301) && headers.location) {
      if (headers.location.includes('dashboard') || 
          headers.location.includes('admin') || 
          headers.location.includes('account') || 
          headers.location.includes('profile') || 
          headers.location.includes('home')) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Detect username enumeration by comparing responses
   * @param {Object} validResponse - Response for valid username
   * @param {Object} invalidResponse - Response for invalid username
   * @returns {boolean} - True if username enumeration is detected, false otherwise
   */
  detectUsernameEnumeration(validResponse, invalidResponse) {
    // Compare response status
    if (validResponse.status !== invalidResponse.status) {
      return true;
    }
    
    // Compare response body
    const validResponseText = typeof validResponse.data === 'string' ? 
      validResponse.data : JSON.stringify(validResponse.data);
    
    const invalidResponseText = typeof invalidResponse.data === 'string' ? 
      invalidResponse.data : JSON.stringify(invalidResponse.data);
    
    // Check for different error messages
    const passwordErrorPatterns = [
      'incorrect password',
      'wrong password',
      'password is invalid',
      'password does not match'
    ];
    
    const usernameErrorPatterns = [
      'user not found',
      'username not found',
      'account not found',
      'user does not exist',
      'username does not exist',
      'account does not exist',
      'no account with that username',
      'no user with that username'
    ];
    
    // Check if valid username response contains password error but not username error
    const hasPasswordError = passwordErrorPatterns.some(pattern => 
      validResponseText.toLowerCase().includes(pattern.toLowerCase())
    );
    
    const hasUsernameError = usernameErrorPatterns.some(pattern => 
      invalidResponseText.toLowerCase().includes(pattern.toLowerCase())
    );
    
    if (hasPasswordError && hasUsernameError) {
      return true;
    }
    
    // Check for significant difference in response length
    const lengthDifference = Math.abs(validResponseText.length - invalidResponseText.length);
    if (lengthDifference > 50) { // Arbitrary threshold
      return true;
    }
    
    return false;
  }

  /**
   * Extract JWT tokens from response
   * @param {Object} response - Axios response object
   * @returns {Array} - Array of JWT tokens
   */
  extractJwtTokens(response) {
    const tokens = [];
    const { data, headers } = response;
    const responseText = typeof data === 'string' ? data : JSON.stringify(data);
    
    // Extract from response body
    const jwtPattern = /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;
    const bodyMatches = responseText.match(jwtPattern);
    
    if (bodyMatches) {
      tokens.push(...bodyMatches);
    }
    
    // Extract from cookies
    if (headers['set-cookie']) {
      const cookies = Array.isArray(headers['set-cookie']) ? 
        headers['set-cookie'] : 
        [headers['set-cookie']];
      
      for (const cookie of cookies) {
        const cookieMatches = cookie.match(jwtPattern);
        if (cookieMatches) {
          tokens.push(...cookieMatches);
        }
      }
    }
    
    // Extract from Authorization header
    if (headers['authorization']) {
      const authMatches = headers['authorization'].match(jwtPattern);
      if (authMatches) {
        tokens.push(...authMatches);
      }
    }
    
    return tokens;
  }

  /**
   * Extract evidence from the response
   * @param {Object} response - Axios response object
   * @returns {string} - Extracted evidence
   */
  extractEvidence(response) {
    const { data, status, headers } = response;
    const responseText = typeof data === 'string' ? data : JSON.stringify(data);
    
    // Return a portion of the response as evidence
    return responseText.substring(0, 200) + (responseText.length > 200 ? '...' : '');
  }
}

module.exports = AuthBypassScanner;

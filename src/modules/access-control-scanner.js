/**
 * Access Control Testing Scanner Module
 * 
 * This module detects access control vulnerabilities by testing for
 * unauthorized access to resources and functionality.
 */

const axios = require('axios');
const { URL } = require('url');
const puppeteer = require('puppeteer');

class AccessControlScanner {
  constructor() {
    this.name = 'access-control-scanner';
    this.description = 'Detects access control vulnerabilities';
  }

  /**
   * Scan target for access control vulnerabilities
   * @param {Object} target - Target information
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async scan(target, options) {
    const findings = [];
    const targetUrl = target.url;
    
    try {
      // Identify protected resources
      const protectedResources = await this.identifyProtectedResources(target, options);
      
      // Test for horizontal privilege escalation
      const horizontalFindings = await this.testHorizontalPrivilegeEscalation(target, protectedResources, options);
      findings.push(...horizontalFindings);
      
      // Test for vertical privilege escalation
      const verticalFindings = await this.testVerticalPrivilegeEscalation(target, protectedResources, options);
      findings.push(...verticalFindings);
      
      // Test for insecure direct object references (IDOR)
      const idorFindings = await this.testIDOR(target, options);
      findings.push(...idorFindings);
      
      // Test for missing function level access control
      const functionLevelFindings = await this.testFunctionLevelAccessControl(target, options);
      findings.push(...functionLevelFindings);
      
      return findings;
    } catch (error) {
      console.error(`Error in access control scan: ${error.message}`);
      return findings;
    }
  }

  /**
   * Identify protected resources that require authentication or authorization
   * @param {Object} target - Target information
   * @param {Object} options - Scanner options
   * @returns {Array} - List of protected resources
   */
  async identifyProtectedResources(target, options) {
    const resources = [];
    
    // If target has protected resources defined, use those
    if (target.protectedResources) {
      return target.protectedResources;
    }
    
    // Common protected paths to check
    const commonProtectedPaths = [
      '/admin',
      '/dashboard',
      '/profile',
      '/account',
      '/settings',
      '/user',
      '/users',
      '/api/users',
      '/api/admin',
      '/api/profile',
      '/api/account',
      '/api/settings',
      '/api/data',
      '/api/private',
      '/api/protected',
      '/api/secure',
      '/api/internal',
      '/manage',
      '/management',
      '/reports',
      '/analytics',
      '/config',
      '/configuration'
    ];
    
    try {
      // First, check if we can access these resources without authentication
      for (const path of commonProtectedPaths) {
        const url = new URL(path, target.url).toString();
        
        const response = await axios.get(url, {
          timeout: options.timeout,
          headers: {
            'User-Agent': options.userAgent
          },
          validateStatus: () => true, // Accept any status code
          maxRedirects: options.followRedirects ? 5 : 0
        });
        
        // If the response indicates authentication is required, add to protected resources
        if (response.status === 401 || 
            response.status === 403 || 
            response.status === 302 || 
            (response.data && typeof response.data === 'string' && 
             (response.data.toLowerCase().includes('login') || 
              response.data.toLowerCase().includes('sign in') || 
              response.data.toLowerCase().includes('unauthorized') || 
              response.data.toLowerCase().includes('forbidden')))) {
          resources.push({
            url: url,
            method: 'GET',
            requiresAuth: true,
            status: response.status
          });
        }
      }
      
      // If we have authentication credentials, try to identify more resources
      if (target.auth && target.auth.credentials) {
        // This would require implementing authentication and crawling
        // For simplicity, we'll skip this part in this implementation
      }
    } catch (error) {
      console.error(`Error identifying protected resources: ${error.message}`);
    }
    
    return resources;
  }

  /**
   * Test for horizontal privilege escalation vulnerabilities
   * @param {Object} target - Target information
   * @param {Array} protectedResources - List of protected resources
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async testHorizontalPrivilegeEscalation(target, protectedResources, options) {
    const findings = [];
    
    // This test requires authenticated access as one user and attempting to access
    // resources belonging to another user at the same privilege level
    // For simplicity, we'll implement a basic version
    
    try {
      // Look for resources with user identifiers in the URL
      const userResourcePatterns = [
        /\/users?\/(\d+)/,
        /\/profiles?\/(\d+)/,
        /\/accounts?\/(\d+)/,
        /\/users?\/([a-zA-Z0-9_-]+)/,
        /\/profiles?\/([a-zA-Z0-9_-]+)/,
        /\/accounts?\/([a-zA-Z0-9_-]+)/,
        /\?id=(\d+)/,
        /\?user_?id=(\d+)/,
        /\?profile_?id=(\d+)/,
        /\?account_?id=(\d+)/
      ];
      
      // If we have authentication credentials, use them
      let authHeaders = {};
      if (target.auth && target.auth.credentials) {
        // This would require implementing authentication
        // For simplicity, we'll skip this part in this implementation
      }
      
      // Test each protected resource for horizontal privilege escalation
      for (const resource of protectedResources) {
        for (const pattern of userResourcePatterns) {
          const match = resource.url.match(pattern);
          
          if (match) {
            const userId = match[1];
            const otherUserIds = this.generateOtherUserIds(userId);
            
            for (const otherId of otherUserIds) {
              const testUrl = resource.url.replace(pattern, (match, id) => match.replace(id, otherId));
              
              const response = await axios({
                method: resource.method,
                url: testUrl,
                headers: {
                  'User-Agent': options.userAgent,
                  ...authHeaders
                },
                timeout: options.timeout,
                validateStatus: () => true,
                maxRedirects: options.followRedirects ? 5 : 0
              });
              
              // Check if we can access another user's resource
              if (response.status === 200) {
                findings.push({
                  type: 'horizontal-privilege-escalation',
                  severity: 'high',
                  confidence: 'medium',
                  url: testUrl,
                  method: resource.method,
                  originalUrl: resource.url,
                  evidence: this.extractEvidence(response),
                  description: `Horizontal privilege escalation vulnerability detected: able to access ${testUrl} which belongs to another user`,
                  remediation: 'Implement proper authorization checks that verify the authenticated user has permission to access the requested resource. Use indirect references instead of direct object references.',
                  cvss: 8.0,
                  cwe: 'CWE-639'
                });
                
                // Break the other ID loop for this resource once we find a vulnerability
                break;
              }
            }
          }
        }
      }
    } catch (error) {
      console.error(`Error testing horizontal privilege escalation: ${error.message}`);
    }
    
    return findings;
  }

  /**
   * Test for vertical privilege escalation vulnerabilities
   * @param {Object} target - Target information
   * @param {Array} protectedResources - List of protected resources
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async testVerticalPrivilegeEscalation(target, protectedResources, options) {
    const findings = [];
    
    // This test requires authenticated access as a lower-privileged user and attempting
    // to access resources restricted to higher-privileged users
    // For simplicity, we'll implement a basic version
    
    try {
      // Common admin/high-privilege paths
      const adminPaths = [
        '/admin',
        '/admin/dashboard',
        '/admin/users',
        '/admin/settings',
        '/admin/config',
        '/admin/reports',
        '/api/admin',
        '/api/admin/users',
        '/api/admin/settings',
        '/api/admin/config',
        '/api/admin/reports',
        '/management',
        '/management/users',
        '/management/settings',
        '/management/config',
        '/management/reports'
      ];
      
      // If we have authentication credentials, use them
      let authHeaders = {};
      if (target.auth && target.auth.credentials) {
        // This would require implementing authentication
        // For simplicity, we'll skip this part in this implementation
      }
      
      // Test each admin path for vertical privilege escalation
      for (const path of adminPaths) {
        const url = new URL(path, target.url).toString();
        
        const response = await axios.get(url, {
          headers: {
            'User-Agent': options.userAgent,
            ...authHeaders
          },
          timeout: options.timeout,
          validateStatus: () => true,
          maxRedirects: options.followRedirects ? 5 : 0
        });
        
        // Check if we can access admin resources
        if (response.status === 200 && 
            !(response.data && typeof response.data === 'string' && 
              (response.data.toLowerCase().includes('login') || 
               response.data.toLowerCase().includes('sign in') || 
               response.data.toLowerCase().includes('unauthorized') || 
               response.data.toLowerCase().includes('forbidden')))) {
          findings.push({
            type: 'vertical-privilege-escalation',
            severity: 'critical',
            confidence: 'medium',
            url: url,
            method: 'GET',
            evidence: this.extractEvidence(response),
            description: `Vertical privilege escalation vulnerability detected: able to access ${url} which should be restricted to administrators`,
            remediation: 'Implement proper role-based access control. Verify user roles and permissions server-side before allowing access to administrative functions.',
            cvss: 9.0,
            cwe: 'CWE-639'
          });
        }
      }
    } catch (error) {
      console.error(`Error testing vertical privilege escalation: ${error.message}`);
    }
    
    return findings;
  }

  /**
   * Test for Insecure Direct Object References (IDOR) vulnerabilities
   * @param {Object} target - Target information
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async testIDOR(target, options) {
    const findings = [];
    
    try {
      // Common URL patterns that might contain direct object references
      const idorPatterns = [
        /\?id=(\d+)/,
        /\?file=([^&]+)/,
        /\?document=([^&]+)/,
        /\?report=([^&]+)/,
        /\?invoice=([^&]+)/,
        /\?order=([^&]+)/,
        /\?payment=([^&]+)/,
        /\?transaction=([^&]+)/,
        /\/(\d+)$/,
        /\/view\/(\d+)/,
        /\/edit\/(\d+)/,
        /\/download\/(\d+)/,
        /\/file\/([^\/]+)/,
        /\/document\/([^\/]+)/,
        /\/report\/([^\/]+)/,
        /\/invoice\/([^\/]+)/,
        /\/order\/([^\/]+)/,
        /\/payment\/([^\/]+)/,
        /\/transaction\/([^\/]+)/
      ];
      
      // First, crawl the site to find potential IDOR endpoints
      const browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
      
      const page = await browser.newPage();
      await page.setUserAgent(options.userAgent);
      
      // Navigate to the target URL
      await page.goto(target.url, { 
        waitUntil: 'networkidle2', 
        timeout: options.timeout 
      });
      
      // Extract all links from the page
      const links = await page.evaluate(() => {
        return Array.from(document.querySelectorAll('a')).map(a => a.href);
      });
      
      await browser.close();
      
      // Filter links that match IDOR patterns
      const idorCandidates = [];
      
      for (const link of links) {
        for (const pattern of idorPatterns) {
          if (pattern.test(link)) {
            const match = link.match(pattern);
            if (match) {
              idorCandidates.push({
                url: link,
                pattern: pattern,
                id: match[1]
              });
            }
          }
        }
      }
      
      // Test each IDOR candidate
      for (const candidate of idorCandidates) {
        // Generate alternative IDs to test
        const alternativeIds = this.generateAlternativeIds(candidate.id);
        
        for (const altId of alternativeIds) {
          const testUrl = candidate.url.replace(candidate.pattern, (match, id) => match.replace(id, altId));
          
          const response = await axios.get(testUrl, {
            timeout: options.timeout,
            headers: {
              'User-Agent': options.userAgent
            },
            validateStatus: () => true,
            maxRedirects: options.followRedirects ? 5 : 0
          });
          
          // Check if we can access the resource with a different ID
          if (response.status === 200) {
            findings.push({
              type: 'insecure-direct-object-reference',
              severity: 'high',
              confidence: 'medium',
              url: testUrl,
              method: 'GET',
              originalUrl: candidate.url,
              evidence: this.extractEvidence(response),
              description: `Insecure Direct Object Reference (IDOR) vulnerability detected: able to access ${testUrl} by manipulating the object reference`,
              remediation: 'Use indirect object references with proper authorization checks. Map the direct references to internal references that are validated against the user\'s access rights.',
              cvss: 7.5,
              cwe: 'CWE-639'
            });
            
            // Break the alternative ID loop for this candidate once we find a vulnerability
            break;
          }
        }
      }
    } catch (error) {
      console.error(`Error testing IDOR: ${error.message}`);
    }
    
    return findings;
  }

  /**
   * Test for missing function level access control vulnerabilities
   * @param {Object} target - Target information
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async testFunctionLevelAccessControl(target, options) {
    const findings = [];
    
    try {
      // Common API endpoints that might have function level access control issues
      const apiEndpoints = [
        '/api/users',
        '/api/users/create',
        '/api/users/update',
        '/api/users/delete',
        '/api/admin',
        '/api/admin/users',
        '/api/admin/settings',
        '/api/settings',
        '/api/config',
        '/api/reports',
        '/api/data',
        '/api/export',
        '/api/import'
      ];
      
      // HTTP methods to test
      const methods = ['GET', 'POST', 'PUT', 'DELETE'];
      
      // Test each API endpoint with different HTTP methods
      for (const endpoint of apiEndpoints) {
        const url = new URL(endpoint, target.url).toString();
        
        for (const method of methods) {
          try {
            const response = await axios({
              method: method,
              url: url,
              headers: {
                'User-Agent': options.userAgent,
                'Content-Type': 'application/json'
              },
              data: method !== 'GET' ? {} : undefined,
              timeout: options.timeout,
              validateStatus: () => true,
              maxRedirects: options.followRedirects ? 5 : 0
            });
            
            // Check if we can access the API endpoint without proper authentication
            if (response.status === 200 || response.status === 201 || response.status === 204) {
              findings.push({
                type: 'missing-function-level-access-control',
                severity: 'high',
                confidence: 'medium',
                url: url,
                method: method,
                evidence: this.extractEvidence(response),
                description: `Missing function level access control vulnerability detected: able to access ${method} ${url} without proper authentication or authorization`,
                remediation: 'Implement proper function level access control checks. Verify user permissions for each function call server-side.',
                cvss: 8.0,
                cwe: 'CWE-285'
              });
            }
          } catch (error) {
            // Ignore errors for individual endpoint tests
            console.error(`Error testing ${method} ${url}: ${error.message}`);
          }
        }
      }
    } catch (error) {
      console.error(`Error testing function level access control: ${error.message}`);
    }
    
    return findings;
  }

  /**
   * Generate alternative IDs for IDOR testing
   * @param {string} id - Original ID
   * @returns {Array} - Array of alternative IDs
   */
  generateAlternativeIds(id) {
    const alternatives = [];
    
    // If ID is numeric
    if (/^\d+$/.test(id)) {
      const numId = parseInt(id, 10);
      
      // Add adjacent IDs
      alternatives.push((numId - 1).toString());
      alternatives.push((numId + 1).toString());
      
      // Add some common IDs
      alternatives.push('1');
      alternatives.push('2');
      alternatives.push('3');
      alternatives.push('100');
    } else {
      // For non-numeric IDs, try some variations
      alternatives.push('admin');
      alternatives.push('test');
      alternatives.push('user');
      alternatives.push('1');
    }
    
    return alternatives;
  }

  /**
   * Generate other user IDs for horizontal privilege escalation testing
   * @param {string} userId - Original user ID
   * @returns {Array} - Array of other user IDs
   */
  generateOtherUserIds(userId) {
    const otherIds = [];
    
    // If user ID is numeric
    if (/^\d+$/.test(userId)) {
      const numId = parseInt(userId, 10);
      
      // Add adjacent user IDs
      otherIds.push((numId - 1).toString());
      otherIds.push((numId + 1).toString());
      
      // Add some common user IDs
      otherIds.push('1');
      otherIds.push('2');
      otherIds.push('3');
      otherIds.push('100');
    } else {
      // For non-numeric user IDs, try some variations
      otherIds.push('admin');
      otherIds.push('test');
      otherIds.push('user');
      otherIds.push('user1');
      otherIds.push('user2');
    }
    
    return otherIds;
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

module.exports = AccessControlScanner;

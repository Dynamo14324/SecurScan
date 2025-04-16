/**
 * Server-Side Request Forgery (SSRF) Scanner Module
 * 
 * This module detects SSRF vulnerabilities by testing parameters that might
 * be used to make server-side requests to internal or external resources.
 */

const axios = require('axios');
const { URL } = require('url');
const { generateSsrfPayloads } = require('../utils/payload-generator');
const { analyzeResponse } = require('../utils/response-analyzer');

class SsrfScanner {
  constructor() {
    this.name = 'ssrf-scanner';
    this.description = 'Detects Server-Side Request Forgery (SSRF) vulnerabilities';
    this.payloads = generateSsrfPayloads();
    this.callbackServer = 'http://example.com/ssrf-callback'; // In a real implementation, this would be a controlled server
  }

  /**
   * Scan target for SSRF vulnerabilities
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
      
      // Identify potential SSRF vulnerable parameters
      const potentialSsrfParams = this.identifyPotentialSsrfParams(paramNames);
      
      // Test each potential SSRF parameter
      for (const param of potentialSsrfParams) {
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
          
          // Analyze the response for SSRF indicators
          const isVulnerable = this.analyzeForSsrf(response, payload);
          
          if (isVulnerable) {
            findings.push({
              type: 'ssrf',
              severity: 'high',
              confidence: 'medium',
              parameter: param,
              payload: payload,
              url: testUrl.toString(),
              evidence: this.extractEvidence(response),
              description: `SSRF vulnerability detected in parameter '${param}'`,
              remediation: 'Implement strict input validation, use allowlists for domains/IPs, disable redirects, use a URL parser to validate URLs, and consider using a separate service for external requests.',
              cvss: 7.5,
              cwe: 'CWE-918'
            });
            
            // Break the payload loop for this parameter once we find a vulnerability
            break;
          }
        }
      }
      
      // Test for blind SSRF using out-of-band detection
      if (options.checkBlindSsrf !== false) {
        const blindSsrfFindings = await this.checkBlindSsrf(target, potentialSsrfParams, options);
        findings.push(...blindSsrfFindings);
      }
      
      return findings;
    } catch (error) {
      console.error(`Error in SSRF scan: ${error.message}`);
      return findings;
    }
  }

  /**
   * Identify parameters that might be vulnerable to SSRF
   * @param {Array} paramNames - List of parameter names
   * @returns {Array} - List of potentially vulnerable parameter names
   */
  identifyPotentialSsrfParams(paramNames) {
    const ssrfKeywords = [
      'url', 'uri', 'link', 'src', 'source', 'redirect', 'return', 'next',
      'site', 'html', 'file', 'document', 'folder', 'root', 'path',
      'reference', 'ref', 'destination', 'dest', 'redirect_to', 'redirecturl',
      'redirect_uri', 'redir', 'image_url', 'imageurl', 'open', 'share',
      'callback', 'callbackurl', 'api', 'endpoint', 'data', 'content',
      'domain', 'host', 'server', 'json', 'xml', 'embed', 'target', 'proxy'
    ];
    
    return paramNames.filter(param => {
      const paramLower = param.toLowerCase();
      return ssrfKeywords.some(keyword => paramLower.includes(keyword));
    });
  }

  /**
   * Analyze response for signs of SSRF vulnerability
   * @param {Object} response - Axios response object
   * @param {string} payload - The payload that was sent
   * @returns {boolean} - True if vulnerable, false otherwise
   */
  analyzeForSsrf(response, payload) {
    const { data, status, headers } = response;
    const responseText = typeof data === 'string' ? data : JSON.stringify(data);
    
    // Check for internal service responses
    const internalServicePatterns = [
      'HTTP/1.1 200 OK Server: Apache',
      'HTTP/1.1 200 OK Server: nginx',
      'HTTP/1.1 200 OK Server: Microsoft-IIS',
      'HTTP/1.1 200 OK Server: SimpleHTTP',
      '<title>Index of /',
      'Directory Listing For',
      'Directory of /',
      'Parent Directory',
      'Forbidden: You don\'t have permission to access',
      'Internal Server Error',
      'The requested URL was rejected',
      'This is a restricted area',
      'Access Denied',
      'Authentication Required'
    ];
    
    for (const pattern of internalServicePatterns) {
      if (responseText.includes(pattern)) {
        return true;
      }
    }
    
    // Check for cloud metadata responses
    const cloudMetadataPatterns = [
      'ami-id',
      'instance-id',
      'instance-type',
      'local-hostname',
      'local-ipv4',
      'public-hostname',
      'public-ipv4',
      'security-groups',
      'user-data',
      'project-id',
      'service-accounts',
      'identity'
    ];
    
    for (const pattern of cloudMetadataPatterns) {
      if (responseText.includes(pattern)) {
        return true;
      }
    }
    
    // Check for internal file content
    const internalFilePatterns = [
      'root:x:0:0:',
      '[boot loader]',
      'uid=0(root) gid=0(root)',
      'Windows Registry Editor',
      '/etc/passwd',
      '/etc/shadow',
      '/etc/hosts',
      '/proc/self/environ',
      'C:\\Windows\\win.ini',
      'C:\\boot.ini'
    ];
    
    for (const pattern of internalFilePatterns) {
      if (responseText.includes(pattern)) {
        return true;
      }
    }
    
    // Check for differences in response status or size compared to normal responses
    // This would require comparing with a baseline response, which is complex for this implementation
    
    return false;
  }

  /**
   * Check for blind SSRF vulnerabilities using out-of-band detection
   * @param {Object} target - Target information
   * @param {Array} paramNames - List of parameter names to test
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async checkBlindSsrf(target, paramNames, options) {
    // In a real implementation, this would use a callback server to detect blind SSRF
    // For this implementation, we'll return an empty array
    return [];
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

module.exports = SsrfScanner;

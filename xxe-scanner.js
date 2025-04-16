/**
 * XML External Entity (XXE) Scanner Module
 * 
 * This module detects XXE vulnerabilities by testing XML inputs for
 * external entity processing vulnerabilities.
 */

const axios = require('axios');
const { URL } = require('url');
const { generateXxePayloads } = require('../utils/payload-generator');
const { analyzeResponse } = require('../utils/response-analyzer');

class XxeScanner {
  constructor() {
    this.name = 'xxe-scanner';
    this.description = 'Detects XML External Entity (XXE) vulnerabilities';
    this.payloads = generateXxePayloads();
  }

  /**
   * Scan target for XXE vulnerabilities
   * @param {Object} target - Target information
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async scan(target, options) {
    const findings = [];
    const targetUrl = target.url;
    
    try {
      // Identify potential XML endpoints
      const xmlEndpoints = await this.identifyXmlEndpoints(target, options);
      
      // Test each potential XML endpoint
      for (const endpoint of xmlEndpoints) {
        for (const payload of this.payloads) {
          // Send the XXE payload to the endpoint
          const response = await this.sendXxePayload(endpoint, payload, options);
          
          // Analyze the response for XXE indicators
          const isVulnerable = this.analyzeForXxe(response, payload);
          
          if (isVulnerable) {
            findings.push({
              type: 'xxe',
              severity: 'high',
              confidence: 'medium',
              endpoint: endpoint.url,
              method: endpoint.method,
              payload: payload,
              evidence: this.extractEvidence(response),
              description: `XXE vulnerability detected in ${endpoint.method} ${endpoint.url}`,
              remediation: 'Disable external entity processing in XML parsers. Use safe XML parsing libraries and configurations. Consider using JSON instead of XML when possible.',
              cvss: 8.2,
              cwe: 'CWE-611'
            });
            
            // Break the payload loop for this endpoint once we find a vulnerability
            break;
          }
        }
      }
      
      // Test for blind XXE using out-of-band detection
      if (options.checkBlindXxe !== false) {
        const blindXxeFindings = await this.checkBlindXxe(target, xmlEndpoints, options);
        findings.push(...blindXxeFindings);
      }
      
      return findings;
    } catch (error) {
      console.error(`Error in XXE scan: ${error.message}`);
      return findings;
    }
  }

  /**
   * Identify endpoints that might accept XML input
   * @param {Object} target - Target information
   * @param {Object} options - Scanner options
   * @returns {Array} - List of potential XML endpoints
   */
  async identifyXmlEndpoints(target, options) {
    const endpoints = [];
    
    // If target has API endpoints defined, check those
    if (target.api && target.api.endpoints) {
      for (const endpoint of target.api.endpoints) {
        if (endpoint.contentType && 
            (endpoint.contentType.includes('xml') || 
             endpoint.contentType.includes('soap'))) {
          endpoints.push({
            url: endpoint.url || target.url + endpoint.path,
            method: endpoint.method || 'POST',
            contentType: endpoint.contentType
          });
        }
      }
    }
    
    // If no XML endpoints were explicitly defined, try common patterns
    if (endpoints.length === 0) {
      const commonXmlEndpoints = [
        { path: '/api/xml', method: 'POST' },
        { path: '/api/data', method: 'POST' },
        { path: '/api/import', method: 'POST' },
        { path: '/api/upload', method: 'POST' },
        { path: '/api/process', method: 'POST' },
        { path: '/api/soap', method: 'POST' },
        { path: '/soap', method: 'POST' },
        { path: '/ws', method: 'POST' },
        { path: '/webservice', method: 'POST' },
        { path: '/service', method: 'POST' },
        { path: '/rpc', method: 'POST' }
      ];
      
      for (const endpoint of commonXmlEndpoints) {
        endpoints.push({
          url: new URL(endpoint.path, target.url).toString(),
          method: endpoint.method,
          contentType: 'application/xml'
        });
      }
    }
    
    return endpoints;
  }

  /**
   * Send XXE payload to an endpoint
   * @param {Object} endpoint - Endpoint information
   * @param {string} payload - XXE payload to send
   * @param {Object} options - Scanner options
   * @returns {Object} - Axios response object
   */
  async sendXxePayload(endpoint, payload, options) {
    try {
      const response = await axios({
        method: endpoint.method,
        url: endpoint.url,
        data: payload,
        headers: {
          'User-Agent': options.userAgent,
          'Content-Type': endpoint.contentType || 'application/xml'
        },
        timeout: options.timeout,
        validateStatus: () => true, // Accept any status code
        maxRedirects: options.followRedirects ? 5 : 0
      });
      
      return response;
    } catch (error) {
      console.error(`Error sending XXE payload: ${error.message}`);
      return {
        status: 0,
        data: '',
        headers: {}
      };
    }
  }

  /**
   * Analyze response for signs of XXE vulnerability
   * @param {Object} response - Axios response object
   * @param {string} payload - The payload that was sent
   * @returns {boolean} - True if vulnerable, false otherwise
   */
  analyzeForXxe(response, payload) {
    const { data, status } = response;
    const responseText = typeof data === 'string' ? data : JSON.stringify(data);
    
    // Check for file content in the response
    const fileContentPatterns = [
      'root:x:0:0:',
      '[boot loader]',
      'uid=0(root) gid=0(root)',
      'Windows Registry Editor',
      '/etc/passwd',
      '/etc/shadow',
      '/etc/group',
      '/etc/hosts',
      '/proc/self/environ',
      'C:\\Windows\\win.ini',
      'C:\\boot.ini',
      'C:\\Windows\\System32\\drivers\\etc\\hosts'
    ];
    
    for (const pattern of fileContentPatterns) {
      if (responseText.includes(pattern)) {
        return true;
      }
    }
    
    // Check for error messages that might indicate XXE processing
    const xxeErrorPatterns = [
      'XML parsing error',
      'XML entity',
      'XML external entity',
      'XXE',
      'DOCTYPE',
      'SYSTEM',
      'ENTITY',
      'XML document structures must start and end within the same entity',
      'Start tag expected',
      'Premature end of data in tag',
      'Error processing external entity',
      'Failed to load external entity'
    ];
    
    for (const pattern of xxeErrorPatterns) {
      if (responseText.includes(pattern)) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Check for blind XXE vulnerabilities using out-of-band detection
   * @param {Object} target - Target information
   * @param {Array} endpoints - List of endpoints to test
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async checkBlindXxe(target, endpoints, options) {
    // In a real implementation, this would use a callback server to detect blind XXE
    // For this implementation, we'll return an empty array
    return [];
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

module.exports = XxeScanner;

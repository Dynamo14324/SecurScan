/**
 * Insecure Deserialization Scanner Module
 * 
 * This module detects insecure deserialization vulnerabilities by testing
 * parameters that might be used to deserialize user-controlled data.
 */

const axios = require('axios');
const { URL } = require('url');
const { generateDeserializationPayloads } = require('../utils/payload-generator');
const { analyzeResponse } = require('../utils/response-analyzer');

class DeserializationScanner {
  constructor() {
    this.name = 'deserialization-scanner';
    this.description = 'Detects insecure deserialization vulnerabilities';
    this.payloads = generateDeserializationPayloads();
  }

  /**
   * Scan target for insecure deserialization vulnerabilities
   * @param {Object} target - Target information
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async scan(target, options) {
    const findings = [];
    const targetUrl = target.url;
    
    try {
      // Identify potential deserialization endpoints
      const endpoints = await this.identifyDeserializationEndpoints(target, options);
      
      // Test each potential endpoint
      for (const endpoint of endpoints) {
        const deserializationFindings = await this.testEndpoint(endpoint, options);
        findings.push(...deserializationFindings);
      }
      
      return findings;
    } catch (error) {
      console.error(`Error in deserialization scan: ${error.message}`);
      return findings;
    }
  }

  /**
   * Identify endpoints that might be vulnerable to insecure deserialization
   * @param {Object} target - Target information
   * @param {Object} options - Scanner options
   * @returns {Array} - List of potential vulnerable endpoints
   */
  async identifyDeserializationEndpoints(target, options) {
    const endpoints = [];
    
    // If target has API endpoints defined, check those
    if (target.api && target.api.endpoints) {
      for (const endpoint of target.api.endpoints) {
        // Check if the endpoint accepts serialized data
        if (endpoint.contentType && 
            (endpoint.contentType.includes('json') || 
             endpoint.contentType.includes('xml') || 
             endpoint.contentType.includes('php') || 
             endpoint.contentType.includes('java') || 
             endpoint.contentType.includes('application/octet-stream'))) {
          endpoints.push({
            url: endpoint.url || target.url + endpoint.path,
            method: endpoint.method || 'POST',
            contentType: endpoint.contentType,
            parameters: endpoint.parameters || []
          });
        }
      }
    }
    
    // Extract parameters from URL that might contain serialized data
    const url = new URL(target.url);
    const params = new URLSearchParams(url.search);
    const paramNames = Array.from(params.keys());
    
    // Look for parameters that might contain serialized data
    const serializationKeywords = [
      'data', 'object', 'serialized', 'json', 'xml', 'state',
      'session', 'token', 'payload', 'obj', 'instance', 'entity',
      'bean', 'model', 'struct', 'param', 'args', 'config'
    ];
    
    const potentialParams = paramNames.filter(param => {
      const paramLower = param.toLowerCase();
      return serializationKeywords.some(keyword => paramLower.includes(keyword));
    });
    
    // Add GET endpoints for potential serialized parameters
    for (const param of potentialParams) {
      endpoints.push({
        url: target.url,
        method: 'GET',
        contentType: 'application/x-www-form-urlencoded',
        parameters: [{ name: param, value: params.get(param) }]
      });
    }
    
    // If no specific endpoints were found, add common endpoints
    if (endpoints.length === 0) {
      const commonEndpoints = [
        { path: '/api/data', method: 'POST', contentType: 'application/json' },
        { path: '/api/object', method: 'POST', contentType: 'application/json' },
        { path: '/api/deserialize', method: 'POST', contentType: 'application/json' },
        { path: '/api/state', method: 'POST', contentType: 'application/json' },
        { path: '/api/import', method: 'POST', contentType: 'application/json' },
        { path: '/api/load', method: 'POST', contentType: 'application/json' }
      ];
      
      for (const endpoint of commonEndpoints) {
        endpoints.push({
          url: new URL(endpoint.path, target.url).toString(),
          method: endpoint.method,
          contentType: endpoint.contentType,
          parameters: []
        });
      }
    }
    
    return endpoints;
  }

  /**
   * Test an endpoint for insecure deserialization vulnerabilities
   * @param {Object} endpoint - Endpoint information
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async testEndpoint(endpoint, options) {
    const findings = [];
    
    // Filter payloads based on content type
    let relevantPayloads = this.payloads;
    
    if (endpoint.contentType) {
      if (endpoint.contentType.includes('json')) {
        relevantPayloads = this.payloads.filter(p => 
          p.includes('_$$ND_FUNC$$_') || 
          p.includes('"rce"') || 
          p.startsWith('{')
        );
      } else if (endpoint.contentType.includes('xml')) {
        relevantPayloads = this.payloads.filter(p => 
          p.includes('<') || 
          p.includes('ResourceDictionary')
        );
      } else if (endpoint.contentType.includes('php')) {
        relevantPayloads = this.payloads.filter(p => 
          p.includes('O:') || 
          p.includes('a:')
        );
      } else if (endpoint.contentType.includes('java')) {
        relevantPayloads = this.payloads.filter(p => 
          p.startsWith('rO0') || 
          p.includes('java.util')
        );
      }
    }
    
    // Test each payload
    for (const payload of relevantPayloads) {
      try {
        let response;
        
        if (endpoint.method === 'GET') {
          // For GET requests, add the payload as a parameter
          const url = new URL(endpoint.url);
          
          for (const param of endpoint.parameters) {
            url.searchParams.set(param.name, payload);
          }
          
          response = await axios.get(url.toString(), {
            timeout: options.timeout,
            headers: {
              'User-Agent': options.userAgent
            },
            validateStatus: () => true, // Accept any status code
            maxRedirects: options.followRedirects ? 5 : 0
          });
        } else {
          // For POST/PUT requests, send the payload in the request body
          let data = payload;
          
          // If the endpoint has specific parameters, create a structured payload
          if (endpoint.parameters && endpoint.parameters.length > 0) {
            if (endpoint.contentType.includes('json')) {
              data = {};
              for (const param of endpoint.parameters) {
                data[param.name] = payload;
              }
              data = JSON.stringify(data);
            } else if (endpoint.contentType.includes('x-www-form-urlencoded')) {
              const params = new URLSearchParams();
              for (const param of endpoint.parameters) {
                params.set(param.name, payload);
              }
              data = params.toString();
            }
          }
          
          response = await axios({
            method: endpoint.method,
            url: endpoint.url,
            data: data,
            headers: {
              'User-Agent': options.userAgent,
              'Content-Type': endpoint.contentType || 'application/json'
            },
            timeout: options.timeout,
            validateStatus: () => true, // Accept any status code
            maxRedirects: options.followRedirects ? 5 : 0
          });
        }
        
        // Analyze the response for deserialization vulnerability indicators
        const isVulnerable = this.analyzeForDeserialization(response, payload);
        
        if (isVulnerable) {
          findings.push({
            type: 'insecure-deserialization',
            severity: 'critical',
            confidence: 'medium',
            endpoint: endpoint.url,
            method: endpoint.method,
            contentType: endpoint.contentType,
            payload: payload,
            evidence: this.extractEvidence(response),
            description: `Insecure deserialization vulnerability detected in ${endpoint.method} ${endpoint.url}`,
            remediation: 'Never deserialize untrusted data. Use safer data formats like JSON with schema validation. Implement integrity checks and consider using serialization libraries with security features.',
            cvss: 9.8,
            cwe: 'CWE-502'
          });
          
          // Break the payload loop for this endpoint once we find a vulnerability
          break;
        }
      } catch (error) {
        console.error(`Error testing deserialization payload: ${error.message}`);
        // Continue with the next payload
      }
    }
    
    return findings;
  }

  /**
   * Analyze response for signs of insecure deserialization vulnerability
   * @param {Object} response - Axios response object
   * @param {string} payload - The payload that was sent
   * @returns {boolean} - True if vulnerable, false otherwise
   */
  analyzeForDeserialization(response, payload) {
    const { data, status } = response;
    const responseText = typeof data === 'string' ? data : JSON.stringify(data);
    
    // Check for command execution indicators
    const commandExecutionPatterns = [
      'uid=',
      'gid=',
      'groups=',
      'Linux version',
      'Darwin Kernel Version',
      'Windows NT',
      'Directory of C:\\',
      'Volume in drive C',
      'Volume Serial Number',
      'Directory of',
      'total ',
      'Filesystem',
      'Mounted on'
    ];
    
    for (const pattern of commandExecutionPatterns) {
      if (responseText.includes(pattern)) {
        return true;
      }
    }
    
    // Check for deserialization error messages
    const deserializationErrorPatterns = [
      'unserialize():',
      'ObjectInputStream',
      'readObject()',
      'Marshal.load',
      'pickle.loads',
      'yaml.load',
      'Unmarshaller',
      'fromXML',
      'parseObject',
      'JSON.parse',
      'deserialize',
      'Deserialize',
      'ReadObject',
      'DESERIALIZE',
      'ClassNotFoundException',
      'java.io.IOException',
      'java.lang.reflect',
      'java.rmi',
      'java.util.concurrent',
      'java.net.URL',
      'java.lang.Runtime',
      'java.lang.Process',
      'ObjectInputStream.readUnshared',
      'com.sun.org.apache.xalan',
      'org.apache.commons.collections',
      'org.springframework',
      'org.hibernate',
      'org.apache.commons.io',
      'org.codehaus.groovy.runtime',
      'org.python.core',
      'org.mozilla.javascript',
      'org.jboss',
      'org.apache.tomcat',
      'org.apache.catalina'
    ];
    
    for (const pattern of deserializationErrorPatterns) {
      if (responseText.includes(pattern)) {
        return true;
      }
    }
    
    // Check for specific payload-based indicators
    if (payload.includes('_$$ND_FUNC$$_') && responseText.includes('child_process')) {
      return true;
    }
    
    if (payload.includes('O:8:"stdClass"') && responseText.includes('system(')) {
      return true;
    }
    
    if (payload.includes('ResourceDictionary') && responseText.includes('Process') && responseText.includes('Start')) {
      return true;
    }
    
    // Check for unusual response status codes that might indicate successful exploitation
    if (status >= 500) {
      return true;
    }
    
    return false;
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

module.exports = DeserializationScanner;

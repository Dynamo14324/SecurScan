/**
 * File Inclusion Vulnerability Scanner Module
 * 
 * This module detects file inclusion vulnerabilities by testing parameters
 * that might be used to include local or remote files.
 */

const axios = require('axios');
const { URL } = require('url');
const { generateFileInclusionPayloads } = require('../utils/payload-generator');
const { analyzeResponse } = require('../utils/response-analyzer');

class FileInclusionScanner {
  constructor() {
    this.name = 'file-inclusion-scanner';
    this.description = 'Detects file inclusion vulnerabilities';
    this.payloads = generateFileInclusionPayloads();
  }

  /**
   * Scan target for file inclusion vulnerabilities
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
      
      // Identify potential file inclusion parameters
      const potentialParams = this.identifyPotentialParams(paramNames);
      
      // Test each potential parameter
      for (const param of potentialParams) {
        const originalValue = params.get(param);
        
        // Test for Local File Inclusion (LFI)
        const lfiFindings = await this.checkLFI(target, param, originalValue, options);
        findings.push(...lfiFindings);
        
        // If LFI is found, don't test for RFI on the same parameter
        if (lfiFindings.length === 0) {
          // Test for Remote File Inclusion (RFI)
          const rfiFindings = await this.checkRFI(target, param, originalValue, options);
          findings.push(...rfiFindings);
        }
      }
      
      return findings;
    } catch (error) {
      console.error(`Error in file inclusion scan: ${error.message}`);
      return findings;
    }
  }

  /**
   * Identify parameters that might be vulnerable to file inclusion
   * @param {Array} paramNames - List of parameter names
   * @returns {Array} - List of potentially vulnerable parameter names
   */
  identifyPotentialParams(paramNames) {
    const keywords = [
      'file', 'page', 'document', 'folder', 'root', 'path',
      'include', 'require', 'doc', 'template', 'theme',
      'module', 'view', 'content', 'layout', 'mod', 'conf',
      'config', 'php', 'style', 'url', 'uri', 'site',
      'inc', 'dir', 'show', 'load', 'read', 'download',
      'upload', 'src', 'source', 'target', 'redir', 'redirect',
      'return', 'next', 'goto', 'display', 'action'
    ];
    
    return paramNames.filter(param => {
      const paramLower = param.toLowerCase();
      return keywords.some(keyword => paramLower.includes(keyword));
    });
  }

  /**
   * Check for Local File Inclusion (LFI) vulnerabilities
   * @param {Object} target - Target information
   * @param {string} param - Parameter name to test
   * @param {string} originalValue - Original parameter value
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async checkLFI(target, param, originalValue, options) {
    const findings = [];
    const targetUrl = target.url;
    const url = new URL(targetUrl);
    
    // Get LFI payloads
    const lfiPayloads = this.payloads.filter(p => 
      p.includes('../') || 
      p.includes('..\\') || 
      p.startsWith('/') || 
      p.includes('%2e%2e') || 
      p.includes('....//') || 
      p.includes('php://') || 
      p.includes('data://')
    );
    
    for (const payload of lfiPayloads) {
      // Create a copy of the parameters
      const testParams = new URLSearchParams(url.search);
      
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
      
      // Analyze the response for LFI indicators
      const isVulnerable = this.analyzeForLFI(response, payload);
      
      if (isVulnerable) {
        findings.push({
          type: 'local-file-inclusion',
          severity: 'high',
          confidence: 'medium',
          parameter: param,
          payload: payload,
          url: testUrl.toString(),
          evidence: this.extractEvidence(response),
          description: `Local File Inclusion vulnerability detected in parameter '${param}'`,
          remediation: 'Avoid using user input to specify file paths. If necessary, implement strict input validation, use allowlists, and consider using indirect file references (e.g., IDs mapped to files).',
          cvss: 7.5,
          cwe: 'CWE-98'
        });
        
        // Break the payload loop for this parameter once we find a vulnerability
        break;
      }
    }
    
    return findings;
  }

  /**
   * Check for Remote File Inclusion (RFI) vulnerabilities
   * @param {Object} target - Target information
   * @param {string} param - Parameter name to test
   * @param {string} originalValue - Original parameter value
   * @param {Object} options - Scanner options
   * @returns {Array} - Array of vulnerability findings
   */
  async checkRFI(target, param, originalValue, options) {
    const findings = [];
    const targetUrl = target.url;
    const url = new URL(targetUrl);
    
    // Get RFI payloads
    const rfiPayloads = this.payloads.filter(p => 
      p.startsWith('http://') || 
      p.startsWith('https://') || 
      p.startsWith('ftp://')
    );
    
    for (const payload of rfiPayloads) {
      // Create a copy of the parameters
      const testParams = new URLSearchParams(url.search);
      
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
      
      // Analyze the response for RFI indicators
      const isVulnerable = this.analyzeForRFI(response, payload);
      
      if (isVulnerable) {
        findings.push({
          type: 'remote-file-inclusion',
          severity: 'critical',
          confidence: 'medium',
          parameter: param,
          payload: payload,
          url: testUrl.toString(),
          evidence: this.extractEvidence(response),
          description: `Remote File Inclusion vulnerability detected in parameter '${param}'`,
          remediation: 'Disable remote file inclusion in your application. Implement strict input validation, use allowlists for file paths, and consider using indirect file references.',
          cvss: 9.8,
          cwe: 'CWE-98'
        });
        
        // Break the payload loop for this parameter once we find a vulnerability
        break;
      }
    }
    
    return findings;
  }

  /**
   * Analyze response for signs of Local File Inclusion vulnerability
   * @param {Object} response - Axios response object
   * @param {string} payload - The payload that was sent
   * @returns {boolean} - True if vulnerable, false otherwise
   */
  analyzeForLFI(response, payload) {
    const { data, status } = response;
    const responseText = typeof data === 'string' ? data : JSON.stringify(data);
    
    // Check for file content patterns
    const fileContentPatterns = [
      'root:x:0:0:',
      '[boot loader]',
      '[fonts]',
      '[extensions]',
      'uid=0(root) gid=0(root)',
      'for 16-bit app support',
      'Define a section for Windows 3.1 compatibility',
      'Windows Registry Editor',
      '<?php',
      '<?=',
      '#!/usr/bin/perl',
      '#!/usr/bin/python',
      '#!/usr/bin/ruby',
      '#!/bin/bash',
      '#!/bin/sh',
      'www-data:x:',
      'daemon:x:',
      'nobody:x:'
    ];
    
    for (const pattern of fileContentPatterns) {
      if (responseText.includes(pattern)) {
        return true;
      }
    }
    
    // Check for specific file content based on the payload
    if (payload.includes('/etc/passwd')) {
      if (responseText.match(/root:.*:0:0:/)) {
        return true;
      }
    }
    
    if (payload.includes('win.ini')) {
      if (responseText.match(/\[fonts\]|\[extensions\]/i)) {
        return true;
      }
    }
    
    // Check for PHP filter-based LFI
    if (payload.includes('php://filter') && payload.includes('base64-encode')) {
      // Look for base64 encoded content in the response
      const base64Regex = /[a-zA-Z0-9+/]{100,}={0,2}/;
      if (base64Regex.test(responseText)) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Analyze response for signs of Remote File Inclusion vulnerability
   * @param {Object} response - Axios response object
   * @param {string} payload - The payload that was sent
   * @returns {boolean} - True if vulnerable, false otherwise
   */
  analyzeForRFI(response, payload) {
    const { data, status } = response;
    const responseText = typeof data === 'string' ? data : JSON.stringify(data);
    
    // Check for indicators that the remote file was included
    // This is a simplified check; in a real scanner, we would use a controlled server
    // and include a unique identifier in the remote file to detect inclusion
    
    // Check if the response contains content from the remote URL
    if (payload.includes('attacker.com') && responseText.includes('RFI_TEST_SUCCESSFUL')) {
      return true;
    }
    
    // Check for PHP execution indicators
    if (responseText.includes('PHP Version') || 
        responseText.includes('phpinfo()') || 
        responseText.includes('PHP Extension')) {
      return true;
    }
    
    // Check for remote code execution indicators
    if (responseText.includes('uid=') || 
        responseText.includes('Windows NT') || 
        responseText.includes('Directory of C:')) {
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

module.exports = FileInclusionScanner;

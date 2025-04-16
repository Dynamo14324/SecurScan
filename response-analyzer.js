/**
 * Response Analyzer Utility
 * 
 * This utility analyzes HTTP responses to detect signs of vulnerabilities
 */

/**
 * Analyze HTTP response for signs of vulnerabilities
 * @param {Object} response - The HTTP response object
 * @param {Object} options - Analysis options
 * @returns {Object} Analysis results
 */
function analyzeResponse(response, options = {}) {
  const results = {
    vulnerabilities: [],
    indicators: [],
    confidence: 'low'
  };

  // Extract response data
  const { data, headers, status } = response;
  const responseText = typeof data === 'string' ? data : JSON.stringify(data);
  
  // Check for SQL injection indicators
  if (options.checkSqlInjection !== false) {
    const sqlInjectionIndicators = detectSqlInjectionIndicators(responseText);
    if (sqlInjectionIndicators.length > 0) {
      results.vulnerabilities.push('sql-injection');
      results.indicators.push(...sqlInjectionIndicators);
      results.confidence = 'medium';
    }
  }
  
  // Check for XSS indicators
  if (options.checkXss !== false) {
    const xssIndicators = detectXssIndicators(responseText);
    if (xssIndicators.length > 0) {
      results.vulnerabilities.push('xss');
      results.indicators.push(...xssIndicators);
      results.confidence = 'medium';
    }
  }
  
  // Check for SSRF indicators
  if (options.checkSsrf !== false) {
    const ssrfIndicators = detectSsrfIndicators(responseText);
    if (ssrfIndicators.length > 0) {
      results.vulnerabilities.push('ssrf');
      results.indicators.push(...ssrfIndicators);
      results.confidence = 'medium';
    }
  }
  
  // Check for XXE indicators
  if (options.checkXxe !== false) {
    const xxeIndicators = detectXxeIndicators(responseText);
    if (xxeIndicators.length > 0) {
      results.vulnerabilities.push('xxe');
      results.indicators.push(...xxeIndicators);
      results.confidence = 'high';
    }
  }
  
  // Check for command injection indicators
  if (options.checkCommandInjection !== false) {
    const commandInjectionIndicators = detectCommandInjectionIndicators(responseText);
    if (commandInjectionIndicators.length > 0) {
      results.vulnerabilities.push('command-injection');
      results.indicators.push(...commandInjectionIndicators);
      results.confidence = 'high';
    }
  }
  
  // Check for file inclusion indicators
  if (options.checkFileInclusion !== false) {
    const fileInclusionIndicators = detectFileInclusionIndicators(responseText);
    if (fileInclusionIndicators.length > 0) {
      results.vulnerabilities.push('file-inclusion');
      results.indicators.push(...fileInclusionIndicators);
      results.confidence = 'medium';
    }
  }
  
  // Check for insecure deserialization indicators
  if (options.checkDeserialization !== false) {
    const deserializationIndicators = detectDeserializationIndicators(responseText);
    if (deserializationIndicators.length > 0) {
      results.vulnerabilities.push('insecure-deserialization');
      results.indicators.push(...deserializationIndicators);
      results.confidence = 'medium';
    }
  }
  
  // Check for authentication bypass indicators
  if (options.checkAuthBypass !== false) {
    const authBypassIndicators = detectAuthBypassIndicators(responseText, headers, status);
    if (authBypassIndicators.length > 0) {
      results.vulnerabilities.push('auth-bypass');
      results.indicators.push(...authBypassIndicators);
      results.confidence = 'medium';
    }
  }
  
  // Check for CSRF indicators
  if (options.checkCsrf !== false) {
    const csrfIndicators = detectCsrfIndicators(headers);
    if (csrfIndicators.length > 0) {
      results.vulnerabilities.push('csrf');
      results.indicators.push(...csrfIndicators);
      results.confidence = 'medium';
    }
  }
  
  return results;
}

/**
 * Detect SQL injection indicators in response text
 * @param {string} responseText - The response text to analyze
 * @returns {Array} Array of indicators found
 */
function detectSqlInjectionIndicators(responseText) {
  const indicators = [];
  
  const sqlErrorPatterns = [
    'SQL syntax',
    'mysql_fetch_array',
    'ORA-',
    'PostgreSQL',
    'SQLite3',
    'SQLSTATE',
    'Microsoft SQL Server',
    'Warning: mysql',
    'Warning: pg_',
    'Warning: sqlite',
    'unclosed quotation mark after the character string',
    'quoted string not properly terminated',
    'You have an error in your SQL syntax',
    'Syntax error or access violation',
    'Incorrect syntax near',
    'ERROR: syntax error at or near',
    'mysql_fetch_assoc()',
    'mysqli_fetch_assoc()',
    'pg_fetch_assoc()',
    'sqlite_fetch_array()',
    'ORA-01756',
    'ORA-00933',
    'ORA-00936',
    'ORA-01789',
    'ORA-01722',
    'ORA-01742',
    'ORA-01747',
    'ORA-01758',
    'ORA-01761',
    'ORA-01789',
    'ORA-12899',
    'SQLSTATE[42000]',
    'SQLSTATE[42S02]',
    'SQLSTATE[HY000]',
    'SQLSTATE[23000]'
  ];
  
  for (const pattern of sqlErrorPatterns) {
    if (responseText.includes(pattern)) {
      indicators.push({
        type: 'sql-error',
        pattern: pattern,
        evidence: extractEvidence(responseText, pattern)
      });
    }
  }
  
  return indicators;
}

/**
 * Detect XSS indicators in response text
 * @param {string} responseText - The response text to analyze
 * @returns {Array} Array of indicators found
 */
function detectXssIndicators(responseText) {
  const indicators = [];
  
  const xssPatterns = [
    '<script>alert(',
    '<img src=x onerror=',
    '<svg onload=',
    'javascript:alert(',
    'onmouseover="alert(',
    "onmouseover='alert(",
    'onfocus="alert(',
    "onfocus='alert("
  ];
  
  for (const pattern of xssPatterns) {
    if (responseText.includes(pattern)) {
      indicators.push({
        type: 'xss-reflection',
        pattern: pattern,
        evidence: extractEvidence(responseText, pattern)
      });
    }
  }
  
  return indicators;
}

/**
 * Detect SSRF indicators in response text
 * @param {string} responseText - The response text to analyze
 * @returns {Array} Array of indicators found
 */
function detectSsrfIndicators(responseText) {
  const indicators = [];
  
  const ssrfPatterns = [
    // AWS metadata
    'ami-id',
    'instance-id',
    'instance-type',
    'local-hostname',
    'local-ipv4',
    'public-hostname',
    'public-ipv4',
    'security-groups',
    'user-data',
    
    // GCP metadata
    'instance/attributes/',
    'instance/service-accounts/',
    'project/project-id',
    
    // Azure metadata
    'metadata/instance',
    'metadata/identity',
    
    // Common internal services
    'HTTP/1.1 200 OK Server: Apache',
    'HTTP/1.1 200 OK Server: nginx',
    'HTTP/1.1 200 OK Server: Microsoft-IIS',
    'HTTP/1.1 200 OK Server: SimpleHTTP',
    
    // Common internal file contents
    'root:x:0:0:',
    '[boot loader]',
    'uid=0(root) gid=0(root)',
    'Windows Registry Editor'
  ];
  
  for (const pattern of ssrfPatterns) {
    if (responseText.includes(pattern)) {
      indicators.push({
        type: 'ssrf-data-leak',
        pattern: pattern,
        evidence: extractEvidence(responseText, pattern)
      });
    }
  }
  
  return indicators;
}

/**
 * Detect XXE indicators in response text
 * @param {string} responseText - The response text to analyze
 * @returns {Array} Array of indicators found
 */
function detectXxeIndicators(responseText) {
  const indicators = [];
  
  const xxePatterns = [
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
  
  for (const pattern of xxePatterns) {
    if (responseText.includes(pattern)) {
      indicators.push({
        type: 'xxe-data-leak',
        pattern: pattern,
        evidence: extractEvidence(responseText, pattern)
      });
    }
  }
  
  return indicators;
}

/**
 * Detect command injection indicators in response text
 * @param {string} responseText - The response text to analyze
 * @returns {Array} Array of indicators found
 */
function detectCommandInjectionIndicators(responseText) {
  const indicators = [];
  
  const commandInjectionPatterns = [
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
  
  for (const pattern of commandInjectionPatterns) {
    if (responseText.includes(pattern)) {
      indicators.push({
        type: 'command-output',
        pattern: pattern,
        evidence: extractEvidence(responseText, pattern)
      });
    }
  }
  
  return indicators;
}

/**
 * Detect file inclusion indicators in response text
 * @param {string} responseText - The response text to analyze
 * @returns {Array} Array of indicators found
 */
function detectFileInclusionIndicators(responseText) {
  const indicators = [];
  
  const fileInclusionPatterns = [
    '<?php',
    '<?=',
    '#!/usr/bin/perl',
    '#!/usr/bin/python',
    '#!/usr/bin/ruby',
    '#!/bin/bash',
    '#!/bin/sh',
    'root:x:0:0:',
    'www-data:x:',
    'daemon:x:',
    'nobody:x:',
    '[boot loader]',
    '[fonts]',
    '[extensions]',
    'uid=0(root) gid=0(root)',
    'for 16-bit app support',
    'Define a section for Windows 3.1 compatibility',
    'Windows Registry Editor',
    'Content-Type: text/html',
    '<!DOCTYPE html>',
    '<html>',
    '<head>',
    '<body>',
    'HTTP/1.1 200 OK',
    'HTTP/1.0 200 OK',
    'Set-Cookie:',
    'Location:'
  ];
  
  for (const pattern of fileInclusionPatterns) {
    if (responseText.includes(pattern)) {
      indicators.push({
        type: 'file-content',
        pattern: pattern,
        evidence: extractEvidence(responseText, pattern)
      });
    }
  }
  
  return indicators;
}

/**
 * Detect insecure deserialization indicators in response text
 * @param {string} responseText - The response text to analyze
 * @returns {Array} Array of indicators found
 */
function detectDeserializationIndicators(responseText) {
  const indicators = [];
  
  const deserializationPatterns = [
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
    'eval(',
    'deserialize',
    'Deserialize',
    'ReadObject',
    'DESERIALIZE',
    'WSDL.deserialize',
    'unsafe.Deserialize'
  ];
  
  for (const pattern of deserializationPatterns) {
    if (responseText.includes(pattern)) {
      indicators.push({
        type: 'deserialization-error',
        pattern: pattern,
        evidence: extractEvidence(responseText, pattern)
      });
    }
  }
  
  return indicators;
}

/**
 * Detect authentication bypass indicators in response text and headers
 * @param {string} responseText - The response text to analyze
 * @param {Object} headers - The response headers
 * @param {number} status - The HTTP status code
 * @returns {Array} Array of indicators found
 */
function detectAuthBypassIndicators(responseText, headers, status) {
  const indicators = [];
  
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
      indicators.push({
        type: 'auth-success-text',
        pattern: pattern,
        evidence: extractEvidence(responseText, pattern, true)
      });
    }
  }
  
  // Check for authentication cookies or tokens in headers
  if (headers['set-cookie']) {
    const cookies = Array.isArray(headers['set-cookie']) 
      ? headers['set-cookie'] 
      : [headers['set-cookie']];
    
    for (const cookie of cookies) {
      if (cookie.toLowerCase().includes('auth') || 
          cookie.toLowerCase().includes('session') || 
          cookie.toLowerCase().includes('token') || 
          cookie.toLowerCase().includes('user') || 
          cookie.toLowerCase().includes('admin') || 
          cookie.toLowerCase().includes('logged')) {
        indicators.push({
          type: 'auth-cookie',
          pattern: cookie.split(';')[0],
          evidence: cookie
        });
      }
    }
  }
  
  // Check for JWT tokens in response
  const jwtPattern = /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;
  const jwtMatches = responseText.match(jwtPattern);
  
  if (jwtMatches) {
    for (const jwt of jwtMatches) {
      indicators.push({
        type: 'jwt-token',
        pattern: 'JWT Token',
        evidence: jwt
      });
    }
  }
  
  // Check for redirect to authenticated area
  if (status === 302 || status === 301) {
    if (headers.location && 
        (headers.location.includes('dashboard') || 
         headers.location.includes('admin') || 
         headers.location.includes('account') || 
         headers.location.includes('profile') || 
         headers.location.includes('home'))) {
      indicators.push({
        type: 'auth-redirect',
        pattern: 'Redirect to authenticated area',
        evidence: `Status: ${status}, Location: ${headers.location}`
      });
    }
  }
  
  return indicators;
}

/**
 * Detect CSRF indicators in headers
 * @param {Object} headers - The response headers
 * @returns {Array} Array of indicators found
 */
function detectCsrfIndicators(headers) {
  const indicators = [];
  
  // Check for missing CSRF protection headers
  const csrfHeaders = [
    'x-csrf-token',
    'csrf-token',
    'x-xsrf-token',
    'xsrf-token',
    'x-csrf',
    'csrf',
    'anti-csrf',
    'x-anti-csrf'
  ];
  
  let csrfHeaderFound = false;
  
  for (const header of csrfHeaders) {
    if (headers[header]) {
      csrfHeaderFound = true;
      break;
    }
  }
  
  if (!csrfHeaderFound) {
    indicators.push({
      type: 'missing-csrf-header',
      pattern: 'No CSRF protection headers',
      evidence: 'No CSRF protection headers found in response'
    });
  }
  
  // Check for missing SameSite cookie attribute
  if (headers['set-cookie']) {
    const cookies = Array.isArray(headers['set-cookie']) 
      ? headers['set-cookie'] 
      : [headers['set-cookie']];
    
    for (const cookie of cookies) {
      if ((cookie.toLowerCase().includes('auth') || 
           cookie.toLowerCase().includes('session') || 
           cookie.toLowerCase().includes('token')) && 
          !cookie.toLowerCase().includes('samesite')) {
        indicators.push({
          type: 'missing-samesite',
          pattern: 'Missing SameSite attribute',
          evidence: cookie
        });
      }
    }
  }
  
  return indicators;
}

/**
 * Extract evidence from response text around a pattern
 * @param {string} text - The text to extract evidence from
 * @param {string} pattern - The pattern to find
 * @param {boolean} caseInsensitive - Whether to use case-insensitive matching
 * @returns {string} The extracted evidence
 */
function extractEvidence(text, pattern, caseInsensitive = false) {
  let index;
  
  if (caseInsensitive) {
    index = text.toLowerCase().indexOf(pattern.toLowerCase());
  } else {
    index = text.indexOf(pattern);
  }
  
  if (index !== -1) {
    const start = Math.max(0, index - 50);
    const end = Math.min(text.length, ind
(Content truncated due to size limit. Use line ranges to read in chunks)
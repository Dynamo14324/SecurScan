/**
 * JavaScript Analysis Module
 * 
 * This module provides functionality for analyzing JavaScript code for security vulnerabilities.
 * It can detect common security issues in client-side JavaScript code.
 */

const esprima = require('esprima');
const estraverse = require('estraverse');
const escodegen = require('escodegen');
const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');

class JavaScriptAnalyzer extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      detectDomXss: options.detectDomXss !== false,
      detectEval: options.detectEval !== false,
      detectDangerousFunctions: options.detectDangerousFunctions !== false,
      detectInsecureRandomness: options.detectInsecureRandomness !== false,
      detectHardcodedSecrets: options.detectHardcodedSecrets !== false,
      detectPrototypePollution: options.detectPrototypePollution !== false,
      detectJsonpVulnerabilities: options.detectJsonpVulnerabilities !== false,
      detectPostMessageVulnerabilities: options.detectPostMessageVulnerabilities !== false,
      detectInsecureStorage: options.detectInsecureStorage !== false,
      logResults: options.logResults !== false,
      logDirectory: options.logDirectory || './logs',
      ...options
    };
    
    // Create log directory if it doesn't exist
    if (this.options.logResults && !fs.existsSync(this.options.logDirectory)) {
      fs.mkdirSync(this.options.logDirectory, { recursive: true });
    }
    
    // Define dangerous functions and patterns
    this.dangerousFunctions = [
      'eval',
      'Function',
      'setTimeout',
      'setInterval',
      'setImmediate',
      'execScript',
      'document.write',
      'document.writeln',
      'document.domain',
      'document.implementation.createHTMLDocument',
      'window.execScript',
      'window.setImmediate',
      'window.open'
    ];
    
    this.domXssSinks = [
      'innerHTML',
      'outerHTML',
      'insertAdjacentHTML',
      'document.write',
      'document.writeln',
      'location',
      'location.href',
      'location.replace',
      'location.assign',
      'jQuery.html',
      'jQuery.append',
      'jQuery.prepend',
      'jQuery.after',
      'jQuery.before',
      'jQuery.replaceWith'
    ];
    
    this.domXssSources = [
      'location',
      'location.href',
      'location.search',
      'location.hash',
      'location.pathname',
      'document.URL',
      'document.documentURI',
      'document.referrer',
      'window.name',
      'document.cookie',
      'localStorage',
      'sessionStorage',
      'history.state',
      'history.pushState',
      'history.replaceState'
    ];
    
    this.insecureRandomnessFunctions = [
      'Math.random'
    ];
    
    this.insecureStorageFunctions = [
      'localStorage.setItem',
      'localStorage.getItem',
      'sessionStorage.setItem',
      'sessionStorage.getItem',
      'document.cookie'
    ];
    
    this.secretPatterns = [
      /api[_-]?key/i,
      /auth[_-]?token/i,
      /access[_-]?token/i,
      /secret[_-]?key/i,
      /private[_-]?key/i,
      /client[_-]?secret/i,
      /password/i,
      /credential/i,
      /secret/i,
      /token/i
    ];
  }

  /**
   * Analyze JavaScript code for security vulnerabilities
   * @param {string} code - JavaScript code to analyze
   * @param {string} source - Source of the code (file path or URL)
   * @returns {Object} - Analysis results
   */
  analyze(code, source = 'unknown') {
    try {
      const findings = [];
      
      // Parse the JavaScript code
      const ast = esprima.parseScript(code, { 
        loc: true, 
        range: true,
        tokens: true,
        comment: true
      });
      
      // Detect DOM XSS vulnerabilities
      if (this.options.detectDomXss) {
        const domXssFindings = this.detectDomXss(ast, code, source);
        findings.push(...domXssFindings);
      }
      
      // Detect eval and other dangerous functions
      if (this.options.detectEval || this.options.detectDangerousFunctions) {
        const dangerousFunctionFindings = this.detectDangerousFunctions(ast, code, source);
        findings.push(...dangerousFunctionFindings);
      }
      
      // Detect insecure randomness
      if (this.options.detectInsecureRandomness) {
        const insecureRandomnessFindings = this.detectInsecureRandomness(ast, code, source);
        findings.push(...insecureRandomnessFindings);
      }
      
      // Detect hardcoded secrets
      if (this.options.detectHardcodedSecrets) {
        const hardcodedSecretFindings = this.detectHardcodedSecrets(ast, code, source);
        findings.push(...hardcodedSecretFindings);
      }
      
      // Detect prototype pollution vulnerabilities
      if (this.options.detectPrototypePollution) {
        const prototypePollutionFindings = this.detectPrototypePollution(ast, code, source);
        findings.push(...prototypePollutionFindings);
      }
      
      // Detect JSONP vulnerabilities
      if (this.options.detectJsonpVulnerabilities) {
        const jsonpFindings = this.detectJsonpVulnerabilities(ast, code, source);
        findings.push(...jsonpFindings);
      }
      
      // Detect postMessage vulnerabilities
      if (this.options.detectPostMessageVulnerabilities) {
        const postMessageFindings = this.detectPostMessageVulnerabilities(ast, code, source);
        findings.push(...postMessageFindings);
      }
      
      // Detect insecure storage
      if (this.options.detectInsecureStorage) {
        const insecureStorageFindings = this.detectInsecureStorage(ast, code, source);
        findings.push(...insecureStorageFindings);
      }
      
      // Log results if enabled
      if (this.options.logResults && findings.length > 0) {
        this.logFindings(findings, source);
      }
      
      // Emit event with findings
      this.emit('analysisCompleted', {
        source: source,
        findingsCount: findings.length,
        findings: findings
      });
      
      return {
        source: source,
        findingsCount: findings.length,
        findings: findings
      };
    } catch (error) {
      this.emit('error', {
        source: source,
        error: error.message,
        stack: error.stack
      });
      
      return {
        source: source,
        error: error.message,
        findingsCount: 0,
        findings: []
      };
    }
  }

  /**
   * Analyze JavaScript file for security vulnerabilities
   * @param {string} filePath - Path to JavaScript file
   * @returns {Object} - Analysis results
   */
  analyzeFile(filePath) {
    try {
      const code = fs.readFileSync(filePath, 'utf8');
      return this.analyze(code, filePath);
    } catch (error) {
      this.emit('error', {
        source: filePath,
        error: error.message,
        stack: error.stack
      });
      
      return {
        source: filePath,
        error: error.message,
        findingsCount: 0,
        findings: []
      };
    }
  }

  /**
   * Analyze multiple JavaScript files for security vulnerabilities
   * @param {Array} filePaths - Array of file paths
   * @returns {Object} - Analysis results
   */
  analyzeFiles(filePaths) {
    const results = {
      totalFiles: filePaths.length,
      analyzedFiles: 0,
      totalFindings: 0,
      fileResults: []
    };
    
    for (const filePath of filePaths) {
      const fileResult = this.analyzeFile(filePath);
      results.analyzedFiles++;
      results.totalFindings += fileResult.findingsCount;
      results.fileResults.push(fileResult);
    }
    
    // Emit event with all results
    this.emit('batchAnalysisCompleted', results);
    
    return results;
  }

  /**
   * Detect DOM XSS vulnerabilities
   * @param {Object} ast - JavaScript AST
   * @param {string} code - Original code
   * @param {string} source - Source of the code
   * @returns {Array} - Array of findings
   */
  detectDomXss(ast, code, source) {
    const findings = [];
    const sourceNodes = [];
    const sinkNodes = [];
    
    // First pass: identify sources and sinks
    estraverse.traverse(ast, {
      enter: (node) => {
        // Check for DOM XSS sources
        if (node.type === 'MemberExpression') {
          const memberExpression = this.getMemberExpressionName(node);
          
          if (this.domXssSources.some(source => memberExpression.includes(source))) {
            sourceNodes.push({
              node: node,
              name: memberExpression,
              loc: node.loc
            });
          }
        }
        
        // Check for DOM XSS sinks
        if (node.type === 'AssignmentExpression' && node.left.type === 'MemberExpression') {
          const memberExpression = this.getMemberExpressionName(node.left);
          
          if (this.domXssSinks.some(sink => memberExpression.endsWith(sink))) {
            sinkNodes.push({
              node: node,
              name: memberExpression,
              loc: node.loc
            });
          }
        } else if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
          const memberExpression = this.getMemberExpressionName(node.callee);
          
          if (this.domXssSinks.some(sink => memberExpression.endsWith(sink))) {
            sinkNodes.push({
              node: node,
              name: memberExpression,
              loc: node.loc
            });
          }
        }
      }
    });
    
    // Second pass: check for data flow from sources to sinks
    for (const sink of sinkNodes) {
      // Get the code for the sink's right side (for assignments) or arguments (for calls)
      let sinkCode = '';
      
      if (sink.node.type === 'AssignmentExpression') {
        sinkCode = code.substring(sink.node.right.range[0], sink.node.right.range[1]);
      } else if (sink.node.type === 'CallExpression') {
        sinkCode = sink.node.arguments.map(arg => 
          code.substring(arg.range[0], arg.range[1])
        ).join(', ');
      }
      
      // Check if any source is used in the sink
      for (const source of sourceNodes) {
        const sourceName = source.name.split('.').pop();
        
        if (sinkCode.includes(sourceName)) {
          findings.push({
            type: 'dom-xss',
            severity: 'high',
            confidence: 'medium',
            source: source.name,
            sink: sink.name,
            location: {
              line: sink.loc.start.line,
              column: sink.loc.start.column,
              file: source
            },
            code: code.substring(sink.node.range[0], sink.node.range[1]),
            description: `Potential DOM XSS vulnerability: ${source.name} flows into ${sink.name}`,
            remediation: 'Sanitize user input before using it in DOM manipulation functions. Use safe DOM APIs like textContent instead of innerHTML.'
          });
        }
      }
    }
    
    return findings;
  }

  /**
   * Detect dangerous functions like eval
   * @param {Object} ast - JavaScript AST
   * @param {string} code - Original code
   * @param {string} source - Source of the code
   * @returns {Array} - Array of findings
   */
  detectDangerousFunctions(ast, code, source) {
    const findings = [];
    
    estraverse.traverse(ast, {
      enter: (node) => {
        // Check for direct eval calls
        if (node.type === 'CallExpression' && 
            node.callee.type === 'Identifier' && 
            node.callee.name === 'eval') {
          findings.push({
            type: 'dangerous-function',
            severity: 'high',
            confidence: 'high',
            function: 'eval',
            location: {
              line: node.loc.start.line,
              column: node.loc.start.column,
              file: source
            },
            code: code.substring(node.range[0], node.range[1]),
            description: 'Use of eval function detected',
            remediation: 'Avoid using eval as it can lead to code injection vulnerabilities. Use safer alternatives like JSON.parse for JSON data.'
          });
        }
        
        // Check for Function constructor
        if (node.type === 'NewExpression' && 
            node.callee.type === 'Identifier' && 
            node.callee.name === 'Function') {
          findings.push({
            type: 'dangerous-function',
            severity: 'high',
            confidence: 'high',
            function: 'Function constructor',
            location: {
              line: node.loc.start.line,
              column: node.loc.start.column,
              file: source
            },
            code: code.substring(node.range[0], node.range[1]),
            description: 'Use of Function constructor detected',
            remediation: 'Avoid using the Function constructor as it can lead to code injection vulnerabilities. Use regular functions instead.'
          });
        }
        
        // Check for other dangerous functions
        if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
          const memberExpression = this.getMemberExpressionName(node.callee);
          
          if (this.dangerousFunctions.includes(memberExpression)) {
            findings.push({
              type: 'dangerous-function',
              severity: 'medium',
              confidence: 'medium',
              function: memberExpression,
              location: {
                line: node.loc.start.line,
                column: node.loc.start.column,
                file: source
              },
              code: code.substring(node.range[0], node.range[1]),
              description: `Use of potentially dangerous function: ${memberExpression}`,
              remediation: `Avoid using ${memberExpression} as it can lead to security vulnerabilities. Use safer alternatives.`
            });
          }
        }
        
        // Check for setTimeout and setInterval with string arguments
        if (node.type === 'CallExpression' && 
            ((node.callee.type === 'Identifier' && 
              (node.callee.name === 'setTimeout' || node.callee.name === 'setInterval')) || 
             (node.callee.type === 'MemberExpression' && 
              this.getMemberExpressionName(node.callee).match(/setTimeout|setInterval/)))) {
          
          if (node.arguments.length > 0 && node.arguments[0].type === 'Literal' && typeof node.arguments[0].value === 'string') {
            findings.push({
              type: 'dangerous-function',
              severity: 'medium',
              confidence: 'high',
              function: node.callee.type === 'Identifier' ? node.callee.name : this.getMemberExpressionName(node.callee),
              location: {
                line: node.loc.start.line,
                column: node.loc.start.column,
                file: source
              },
              code: code.substring(node.range[0], node.range[1]),
              description: 'Use of setTimeout/setInterval with string argument',
              remediation: 'Avoid using setTimeout or setInterval with string arguments as they use eval internally. Use function references instead.'
            });
          }
        }
      }
    });
    
    return findings;
  }

  /**
   * Detect insecure randomness
   * @param {Object} ast - JavaScript AST
   * @param {string} code - Original code
   * @param {string} source - Source of the code
   * @returns {Array} - Array of findings
   */
  detectInsecureRandomness(ast, code, source) {
    const findings = [];
    
    estraverse.traverse(ast, {
      enter: (node) => {
        if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
          const memberExpression = this.getMemberExpressionName(node.callee);
          
          if (this.insecureRandomnessFunctions.includes(memberExpression)) {
            // Check if it's used in a security context
            const parentFunction = this.findParentFuncti
(Content truncated due to size limit. Use line ranges to read in chunks)
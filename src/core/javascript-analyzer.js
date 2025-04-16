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
            const parentFunction = this.findParentFunction(ast, node);
            const functionName = parentFunction ? this.getFunctionName(parentFunction) : null;
            
            const securityContextKeywords = [
              'token', 'key', 'secret', 'password', 'auth', 'id', 'session', 'random', 'uuid', 'guid'
            ];
            
            const isSecurityContext = functionName && 
              securityContextKeywords.some(keyword => functionName.toLowerCase().includes(keyword));
            
            if (isSecurityContext) {
              findings.push({
                type: 'insecure-randomness',
                severity: 'medium',
                confidence: 'medium',
                function: memberExpression,
                location: {
                  line: node.loc.start.line,
                  column: node.loc.start.column,
                  file: source
                },
                code: code.substring(node.range[0], node.range[1]),
                description: `Use of insecure randomness function in security context: ${memberExpression}`,
                remediation: 'Use cryptographically secure random number generation like crypto.getRandomValues() instead of Math.random() for security-sensitive operations.'
              });
            }
          }
        }
      }
    });
    
    return findings;
  }

  /**
   * Detect hardcoded secrets
   * @param {Object} ast - JavaScript AST
   * @param {string} code - Original code
   * @param {string} source - Source of the code
   * @returns {Array} - Array of findings
   */
  detectHardcodedSecrets(ast, code, source) {
    const findings = [];
    
    estraverse.traverse(ast, {
      enter: (node) => {
        // Check variable declarations
        if (node.type === 'VariableDeclarator' && 
            node.id.type === 'Identifier' && 
            node.init && 
            node.init.type === 'Literal' && 
            typeof node.init.value === 'string') {
          
          const variableName = node.id.name;
          const variableValue = node.init.value;
          
          // Check if variable name suggests a secret
          if (this.secretPatterns.some(pattern => pattern.test(variableName))) {
            findings.push({
              type: 'hardcoded-secret',
              severity: 'high',
              confidence: 'medium',
              secretType: this.getSecretType(variableName),
              location: {
                line: node.loc.start.line,
                column: node.loc.start.column,
                file: source
              },
              code: code.substring(node.range[0], node.range[1]),
              description: `Hardcoded secret detected: ${variableName}`,
              remediation: 'Avoid hardcoding secrets in your code. Use environment variables or a secure secret management system.'
            });
          }
        }
        
        // Check object properties
        if (node.type === 'Property' && 
            node.key.type === 'Identifier' && 
            node.value && 
            node.value.type === 'Literal' && 
            typeof node.value.value === 'string') {
          
          const propertyName = node.key.name;
          const propertyValue = node.value.value;
          
          // Check if property name suggests a secret
          if (this.secretPatterns.some(pattern => pattern.test(propertyName))) {
            findings.push({
              type: 'hardcoded-secret',
              severity: 'high',
              confidence: 'medium',
              secretType: this.getSecretType(propertyName),
              location: {
                line: node.loc.start.line,
                column: node.loc.start.column,
                file: source
              },
              code: code.substring(node.range[0], node.range[1]),
              description: `Hardcoded secret detected in object property: ${propertyName}`,
              remediation: 'Avoid hardcoding secrets in your code. Use environment variables or a secure secret management system.'
            });
          }
        }
      }
    });
    
    return findings;
  }

  /**
   * Detect prototype pollution vulnerabilities
   * @param {Object} ast - JavaScript AST
   * @param {string} code - Original code
   * @param {string} source - Source of the code
   * @returns {Array} - Array of findings
   */
  detectPrototypePollution(ast, code, source) {
    const findings = [];
    
    estraverse.traverse(ast, {
      enter: (node) => {
        // Check for dynamic property assignment with user input
        if (node.type === 'AssignmentExpression' && 
            node.left.type === 'MemberExpression' && 
            node.left.computed === true) {
          
          // Check if the property name comes from user input
          const propertyNode = node.left.property;
          const userInputSources = [
            'location', 'document.URL', 'document.documentURI', 'document.referrer',
            'window.name', 'history.state', 'XMLHttpRequest', 'fetch', 'jQuery.param'
          ];
          
          let isUserControlled = false;
          
          if (propertyNode.type === 'Identifier') {
            // Check if the identifier is derived from user input
            const variableName = propertyNode.name;
            
            // Simple check: look for variable declarations that get values from user input
            estraverse.traverse(ast, {
              enter: (innerNode) => {
                if (innerNode.type === 'VariableDeclarator' && 
                    innerNode.id.type === 'Identifier' && 
                    innerNode.id.name === variableName) {
                  
                  if (innerNode.init && innerNode.init.type === 'MemberExpression') {
                    const memberExpression = this.getMemberExpressionName(innerNode.init);
                    
                    if (userInputSources.some(source => memberExpression.includes(source))) {
                      isUserControlled = true;
                    }
                  }
                }
              }
            });
          } else if (propertyNode.type === 'MemberExpression') {
            const memberExpression = this.getMemberExpressionName(propertyNode);
            
            if (userInputSources.some(source => memberExpression.includes(source))) {
              isUserControlled = true;
            }
          }
          
          if (isUserControlled) {
            findings.push({
              type: 'prototype-pollution',
              severity: 'high',
              confidence: 'medium',
              location: {
                line: node.loc.start.line,
                column: node.loc.start.column,
                file: source
              },
              code: code.substring(node.range[0], node.range[1]),
              description: 'Potential prototype pollution vulnerability: dynamic property assignment with user-controlled input',
              remediation: 'Validate and sanitize user input before using it as an object property name. Consider using Object.create(null) to create objects without a prototype.'
            });
          }
        }
        
        // Check for recursive merge/extend functions
        if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') {
          const functionName = this.getFunctionName(node);
          
          if (functionName && 
              (functionName.includes('merge') || 
               functionName.includes('extend') || 
               functionName.includes('assign') || 
               functionName.includes('clone') || 
               functionName.includes('copy'))) {
            
            // Check if the function has recursive property assignment
            let hasRecursiveAssignment = false;
            let hasPropertyCheck = false;
            
            estraverse.traverse(node, {
              enter: (innerNode) => {
                // Check for recursive calls
                if (innerNode.type === 'CallExpression' && 
                    ((innerNode.callee.type === 'Identifier' && innerNode.callee.name === functionName) || 
                     (innerNode.callee.type === 'MemberExpression' && this.getMemberExpressionName(innerNode.callee).endsWith(functionName)))) {
                  hasRecursiveAssignment = true;
                }
                
                // Check for property name validation
                if (innerNode.type === 'IfStatement') {
                  const condition = code.substring(innerNode.test.range[0], innerNode.test.range[1]);
                  
                  if (condition.includes('__proto__') || 
                      condition.includes('prototype') || 
                      condition.includes('constructor')) {
                    hasPropertyCheck = true;
                  }
                }
              }
            });
            
            if (hasRecursiveAssignment && !hasPropertyCheck) {
              findings.push({
                type: 'prototype-pollution',
                severity: 'medium',
                confidence: 'medium',
                function: functionName,
                location: {
                  line: node.loc.start.line,
                  column: node.loc.start.column,
                  file: source
                },
                code: code.substring(node.range[0], node.range[1]).substring(0, 100) + '...',
                description: `Potential prototype pollution in recursive object merge function: ${functionName}`,
                remediation: 'Implement proper property name validation in recursive merge functions. Check for dangerous properties like __proto__, constructor, and prototype.'
              });
            }
          }
        }
      }
    });
    
    return findings;
  }

  /**
   * Detect JSONP vulnerabilities
   * @param {Object} ast - JavaScript AST
   * @param {string} code - Original code
   * @param {string} source - Source of the code
   * @returns {Array} - Array of findings
   */
  detectJsonpVulnerabilities(ast, code, source) {
    const findings = [];
    
    estraverse.traverse(ast, {
      enter: (node) => {
        // Check for script tag creation with dynamic src
        if (node.type === 'CallExpression' && 
            node.callee.type === 'MemberExpression' && 
            this.getMemberExpressionName(node.callee) === 'document.createElement' && 
            node.arguments.length > 0 && 
            node.arguments[0].type === 'Literal' && 
            node.arguments[0].value === 'script') {
          
          // Look for subsequent src assignment
          const parent = this.findParent(ast, node);
          
          if (parent && parent.type === 'VariableDeclarator') {
            const scriptVarName = parent.id.name;
            
            // Find where the src is set
            estraverse.traverse(ast, {
              enter: (innerNode) => {
                if (innerNode.type === 'AssignmentExpression' && 
                    innerNode.left.type === 'MemberExpression' && 
                    innerNode.left.object.type === 'Identifier' && 
                    innerNode.left.object.name === scriptVarName && 
                    innerNode.left.property.type === 'Identifier' && 
                    innerNode.left.property.name === 'src') {
                  
                  // Check if the src contains user input
                  const srcCode = code.substring(innerNode.right.range[0], innerNode.right.range[1]);
                  
                  if (srcCode.includes('location') || 
                      srcCode.includes('document.URL') || 
                      srcCode.includes('document.referrer') || 
                      srcCode.includes('window.name')) {
                    
                    findings.push({
                      type: 'jsonp-vulnerability',
                      severity: 'high',
                      confidence: 'medium',
                      location: {
                        line: innerNode.loc.start.line,
                        column: innerNode.loc.start.column,
                        file: source
                      },
                      code: code.substring(innerNode.range[0], innerNode.range[1]),
                      description: 'Potential JSONP vulnerability: dynamic script src with user-controlled input',
                      remediation: 'Validate the JSONP callback and URL. Use CORS instead of JSONP when possible.'
                    });
                  }
                }
              }
            });
          }
        }
        
        // Check for JSONP callback parameter in URLs
        if (node.type === 'Literal' && 
            typeof node.value === 'string' && 
            (node.value.includes('callback=') || node.value.includes('jsonp='))) {
          
          findings.push({
            type: 'jsonp-vulnerability',
            severity: 'low',
            confidence: 'low',
            location: {
              line: node.loc.start.line,
              column: node.loc.start.column,
              file: source
            },
            code: code.substring(node.range[0], node.range[1]),
            description: 'JSONP usage detected',
            remediation: 'Consider using CORS instead of JSONP. If JSONP is necessary, validate the callback parameter and implement proper Content Security Policy.'
          });
        }
      }
    });
    
    return findings;
  }

  /**
   * Detect postMessage vulnerabilities
   * @param {Object} ast - JavaScript AST
   * @param {string} code - Original code
   * @param {string} source - Source of the code
   * @returns {Array} - Array of findings
   */
  detectPostMessageVulnerabilities(ast, code, source) {
    const findings = [];
    
    // Find postMessage calls
    const postMessageCalls = [];
    const messageEventListeners = [];
    
    estraverse.traverse(ast, {
      enter: (node) => {
        // Check for postMessage calls
        if (node.type === 'CallExpression' && 
            node.callee.type === 'MemberExpression' && 
            node.callee.property.type === 'Identifier' && 
            node.callee.property.name === 'postMessage') {
          
          postMessageCalls.push({
            node: node,
            targetOrigin: node.arguments.length > 1 ? node.arguments[1] : null
          });
        }
        
        // Check for message event listeners
        if (node.type === 'CallExpression' && 
            node.callee.type === 'MemberExpression' && 
            node.callee.property.type === 'Identifier' && 
            node.callee.property.name === 'addEventListener' && 
            node.arguments.length > 1 && 
            node.arguments[0].type === 'Literal' && 
            node.arguments[0].value === 'message') {
          
          messageEventListeners.push({
            node: node,
            handler: node.arguments[1]
          });
        }
      }
    });
    
    // Check postMessage calls for wildcard origin
    for (const call of postMessageCalls) {
      if (call.targetOrigin && 
          call.targetOrigin.type === 'Literal' && 
          call.targetOrigin.value === '*') {
        
        findings.push({
          type: 'postmessage-vulnerability',
          severity: 'medium',
          confidence: 'high',
          location: {
            line: call.node.loc.start.line,
            column: call.node.loc.start.column,
            file: source
          },
          code: code.substring(call.node.range[0], call.node.range[1]),
          description: 'Insecure postMessage: using wildcard (*) target origin',
          remediation: 'Specify a concrete target origin instead of using the wildcard (*) when sending messages with postMessage.'
        });
      }
    }
    
    // Check message event handlers for origin validation
    for (const listener of messageEventListeners) {
      let hasOriginCheck = false;
      
      // If the handler is a function expression, check its body
      if (listener.handler.type === 'FunctionExpression' || 
          listener.handler.type === 'ArrowFunctionExpression') {
        
        estraverse.traverse(listener.handler, {
          enter: (node) => {
            if (node.type === 'MemberExpression' && 
                node.property.type === 'Identifier' && 
                node.property.name === 'origin') {
              
              // Check if it's used in a condition
              const parent = this.findParent(ast, node);
              
              if (parent && 
                  (parent.type === 'BinaryExpression' || 
                   parent.type === 'IfStatement' || 
                   parent.type === 'ConditionalExpression')) {
                hasOriginCheck = true;
              }
            }
          }
        });
        
        if (!hasOriginCheck) {
          findings.push({
            type: 'postmessage-vulnerability',
            severity: 'medium',
            confidence: 'medium',
            location: {
              line: listener.node.loc.start.line,
              column: listener.node.loc.start.column,
              file: source
            },
            code: code.substring(listener.node.range[0], listener.node.range[1]),
            description: 'Insecure message event listener: no origin validation',
            remediation: 'Always validate the origin of incoming messages in postMessage event listeners.'
          });
        }
      }
    }
    
    return findings;
  }

  /**
   * Detect insecure storage
   * @param {Object} ast - JavaScript AST
   * @param {string} code - Original code
   * @param {string} source - Source of the code
   * @returns {Array} - Array of findings
   */
  detectInsecureStorage(ast, code, source) {
    const findings = [];
    
    estraverse.traverse(ast, {
      enter: (node) => {
        // Check for localStorage and sessionStorage usage with sensitive data
        if (node.type === 'CallExpression' && 
            node.callee.type === 'MemberExpression') {
          
          const memberExpression = this.getMemberExpressionName(node.callee);
          
          if (this.insecureStorageFunctions.includes(memberExpression)) {
            // Check if storing sensitive data
            if (node.arguments.length > 0) {
              const arg = node.arguments[0];
              
              if (arg.type === 'Literal' && typeof arg.value === 'string') {
                const key = arg.value.toLowerCase();
                
                if (key.includes('token') || 
                    key.includes('auth') || 
                    key.includes('password') || 
                    key.includes('secret') || 
                    key.includes('key') || 
                    key.includes('credential')) {
                  
                  findings.push({
                    type: 'insecure-storage',
                    severity: 'medium',
                    confidence: 'medium',
                    storage: memberExpression.split('.')[0],
                    key: arg.value,
                    location: {
                      line: node.loc.start.line,
                      column: node.loc.start.column,
                      file: source
                    },
                    code: code.substring(node.range[0], node.range[1]),
                    description: `Sensitive data stored in ${memberExpression.split('.')[0]}: ${arg.value}`,
                    remediation: 'Avoid storing sensitive data in localStorage or sessionStorage. Use secure storage mechanisms like HttpOnly cookies for sensitive data.'
                  });
                }
              }
            }
          }
        }
        
        // Check for document.cookie with sensitive data
        if (node.type === 'AssignmentExpression' && 
            node.left.type === 'MemberExpression' && 
            this.getMemberExpressionName(node.left) === 'document.cookie') {
          
          const cookieString = code.substring(node.right.range[0], node.right.range[1]);
          
          if (!cookieString.includes('Secure') || !cookieString.includes('HttpOnly')) {
            findings.push({
              type: 'insecure-cookie',
              severity: 'medium',
              confidence: 'medium',
              location: {
                line: node.loc.start.line,
                column: node.loc.start.column,
                file: source
              },
              code: code.substring(node.range[0], node.range[1]),
              description: 'Insecure cookie: missing Secure and/or HttpOnly flags',
              remediation: 'Set the Secure and HttpOnly flags for all cookies containing sensitive information.'
            });
          }
          
          if (cookieString.toLowerCase().includes('token=') || 
              cookieString.toLowerCase().includes('auth=') || 
              cookieString.toLowerCase().includes('session=') || 
              cookieString.toLowerCase().includes('jwt=')) {
            
            findings.push({
              type: 'insecure-cookie',
              severity: 'medium',
              confidence: 'medium',
              location: {
                line: node.loc.start.line,
                column: node.loc.start.column,
                file: source
              },
              code: code.substring(node.range[0], node.range[1]),
              description: 'Sensitive data stored in cookie',
              remediation: 'Ensure cookies with sensitive data have the Secure and HttpOnly flags set. Consider using server-side session management.'
            });
          }
        }
      }
    });
    
    return findings;
  }

  /**
   * Get the name of a member expression
   * @param {Object} node - AST node
   * @returns {string} - Member expression name
   */
  getMemberExpressionName(node) {
    if (node.type !== 'MemberExpression') {
      return '';
    }
    
    if (node.object.type === 'MemberExpression') {
      return this.getMemberExpressionName(node.object) + '.' + (node.property.name || node.property.value);
    } else if (node.object.type === 'Identifier') {
      return node.object.name + '.' + (node.property.name || node.property.value);
    }
    
    return '';
  }

  /**
   * Find the parent node of a given node
   * @param {Object} ast - JavaScript AST
   * @param {Object} targetNode - Target node
   * @returns {Object|null} - Parent node or null
   */
  findParent(ast, targetNode) {
    let parent = null;
    
    estraverse.traverse(ast, {
      enter: function(node, parentNode) {
        if (node === targetNode) {
          parent = parentNode;
          this.break();
        }
      }
    });
    
    return parent;
  }

  /**
   * Find the parent function of a given node
   * @param {Object} ast - JavaScript AST
   * @param {Object} targetNode - Target node
   * @returns {Object|null} - Parent function node or null
   */
  findParentFunction(ast, targetNode) {
    let parentFunction = null;
    let currentNode = targetNode;
    
    while (!parentFunction && currentNode) {
      const parent = this.findParent(ast, currentNode);
      
      if (!parent) {
        break;
      }
      
      if (parent.type === 'FunctionDeclaration' || 
          parent.type === 'FunctionExpression' || 
          parent.type === 'ArrowFunctionExpression') {
        parentFunction = parent;
      }
      
      currentNode = parent;
    }
    
    return parentFunction;
  }

  /**
   * Get the name of a function
   * @param {Object} node - Function node
   * @returns {string|null} - Function name or null
   */
  getFunctionName(node) {
    if (node.type === 'FunctionDeclaration' && node.id) {
      return node.id.name;
    } else if (node.type === 'FunctionExpression' && node.id) {
      return node.id.name;
    } else if (node.type === 'VariableDeclarator' && 
               node.init && 
               (node.init.type === 'FunctionExpression' || node.init.type === 'ArrowFunctionExpression')) {
      return node.id.name;
    } else if (node.type === 'AssignmentExpression' && 
               node.right && 
               (node.right.type === 'FunctionExpression' || node.right.type === 'ArrowFunctionExpression')) {
      if (node.left.type === 'Identifier') {
        return node.left.name;
      } else if (node.left.type === 'MemberExpression') {
        return this.getMemberExpressionName(node.left);
      }
    } else if (node.type === 'Property' && 
               node.value && 
               (node.value.type === 'FunctionExpression' || node.value.type === 'ArrowFunctionExpression')) {
      return node.key.name || node.key.value;
    } else if (node.type === 'MethodDefinition') {
      return node.key.name || node.key.value;
    }
    
    return null;
  }

  /**
   * Get the type of a secret based on its name
   * @param {string} name - Secret name
   * @returns {string} - Secret type
   */
  getSecretType(name) {
    name = name.toLowerCase();
    
    if (name.includes('api') && name.includes('key')) {
      return 'API Key';
    } else if (name.includes('token')) {
      return 'Token';
    } else if (name.includes('secret')) {
      return 'Secret';
    } else if (name.includes('password')) {
      return 'Password';
    } else if (name.includes('credential')) {
      return 'Credential';
    } else if (name.includes('key')) {
      return 'Key';
    } else {
      return 'Unknown';
    }
  }

  /**
   * Log findings to file
   * @param {Array} findings - Array of findings
   * @param {string} source - Source of the code
   */
  logFindings(findings, source) {
    try {
      const logFile = path.join(
        this.options.logDirectory,
        `js_analysis_${Date.now()}.json`
      );
      
      const logData = {
        source: source,
        timestamp: Date.now(),
        findingsCount: findings.length,
        findings: findings
      };
      
      fs.writeFileSync(logFile, JSON.stringify(logData, null, 2));
    } catch (error) {
      console.error('Error logging findings:', error);
    }
  }
}

module.exports = JavaScriptAnalyzer;

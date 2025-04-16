/**
 * Custom Scan Policy Module
 * 
 * This module provides functionality for creating and managing custom scan policies
 * to control the behavior of security scans.
 */

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class CustomScanPolicy extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      logResults: options.logResults !== false,
      logDirectory: options.logDirectory || './logs',
      ...options
    };
    
    // Create log directory if it doesn't exist
    if (this.options.logResults && !fs.existsSync(this.options.logDirectory)) {
      fs.mkdirSync(this.options.logDirectory, { recursive: true });
    }
    
    // Default scan policy
    this.defaultPolicy = {
      id: 'default',
      name: 'Default Scan Policy',
      description: 'Default scan policy with all checks enabled',
      createdAt: Date.now(),
      updatedAt: Date.now(),
      vulnerabilityChecks: {
        sqlInjection: {
          enabled: true,
          severity: 'high',
          options: {
            testParameters: true,
            testHeaders: true,
            testCookies: true,
            testJsonBody: true,
            payloadLevel: 'medium'
          }
        },
        xss: {
          enabled: true,
          severity: 'high',
          options: {
            testParameters: true,
            testHeaders: true,
            testCookies: true,
            testJsonBody: true,
            testDomXss: true,
            payloadLevel: 'medium'
          }
        },
        csrf: {
          enabled: true,
          severity: 'high',
          options: {
            testForms: true,
            testTokens: true
          }
        },
        ssrf: {
          enabled: true,
          severity: 'high',
          options: {
            testParameters: true,
            testHeaders: true,
            testJsonBody: true,
            payloadLevel: 'medium'
          }
        },
        xxe: {
          enabled: true,
          severity: 'high',
          options: {
            testXmlInput: true,
            testContentType: true,
            payloadLevel: 'medium'
          }
        },
        commandInjection: {
          enabled: true,
          severity: 'high',
          options: {
            testParameters: true,
            testHeaders: true,
            testJsonBody: true,
            payloadLevel: 'medium'
          }
        },
        fileInclusion: {
          enabled: true,
          severity: 'high',
          options: {
            testParameters: true,
            testHeaders: true,
            testJsonBody: true,
            payloadLevel: 'medium'
          }
        },
        insecureDeserialization: {
          enabled: true,
          severity: 'high',
          options: {
            testJsonInput: true,
            testXmlInput: true,
            testPhpInput: true,
            testJavaInput: true,
            payloadLevel: 'medium'
          }
        },
        authBypass: {
          enabled: true,
          severity: 'high',
          options: {
            testDirectAccess: true,
            testParameterTampering: true,
            testRoleEscalation: true
          }
        },
        accessControl: {
          enabled: true,
          severity: 'high',
          options: {
            testHorizontalEscalation: true,
            testVerticalEscalation: true,
            testDirectObjectReferences: true
          }
        }
      },
      technicalOptions: {
        headlessBrowser: {
          enabled: true,
          options: {
            timeout: 30000,
            waitTime: 1000,
            viewport: { width: 1366, height: 768 },
            userAgent: 'SecurScan Pro Security Scanner'
          }
        },
        proxyInterception: {
          enabled: true,
          options: {
            port: 8080,
            interceptRequest: true,
            interceptResponse: true,
            logTraffic: true
          }
        },
        httpRequestCrafting: {
          enabled: true,
          options: {
            timeout: 30000,
            followRedirects: true,
            maxRedirects: 5,
            validateStatus: null
          }
        },
        javascriptAnalysis: {
          enabled: true,
          options: {
            detectDomXss: true,
            detectEval: true,
            detectDangerousFunctions: true,
            detectInsecureRandomness: true,
            detectHardcodedSecrets: true,
            detectPrototypePollution: true,
            detectJsonpVulnerabilities: true,
            detectPostMessageVulnerabilities: true,
            detectInsecureStorage: true
          }
        },
        apiEndpointDiscovery: {
          enabled: true,
          options: {
            maxDepth: 3,
            maxPages: 100,
            followRedirects: true,
            timeout: 10000,
            concurrency: 5
          }
        },
        intelligentCrawling: {
          enabled: true,
          options: {
            maxDepth: 3,
            maxPages: 100,
            maxConcurrency: 5,
            timeout: 30000,
            waitTime: 1000,
            clickElements: true,
            fillForms: true
          }
        },
        authenticationHandling: {
          enabled: true,
          options: {
            timeout: 30000,
            waitTime: 1000
          }
        },
        sessionManagement: {
          enabled: true,
          options: {
            timeout: 30000,
            waitTime: 1000
          }
        }
      },
      scanThrottling: {
        enabled: true,
        options: {
          requestsPerSecond: 10,
          maxConcurrentRequests: 5,
          delayBetweenRequests: 100,
          respectRobotsTxt: true,
          respectMetaRobots: true
        }
      },
      reporting: {
        includeEvidence: true,
        includeCvss: true,
        includeRemediation: true,
        includeProofOfConcept: true,
        formats: ['html', 'pdf', 'json']
      }
    };
    
    // Initialize policies storage
    this.policies = new Map();
    this.policies.set('default', this.defaultPolicy);
    
    // Try to load saved policies
    this.loadPolicies();
  }

  /**
   * Create a new scan policy
   * @param {Object} policy - Scan policy configuration
   * @returns {Object} - Created policy
   */
  createPolicy(policy) {
    try {
      // Generate policy ID if not provided
      if (!policy.id) {
        policy.id = crypto.randomBytes(8).toString('hex');
      }
      
      // Set creation and update timestamps
      policy.createdAt = Date.now();
      policy.updatedAt = Date.now();
      
      // Validate policy
      this.validatePolicy(policy);
      
      // Store policy
      this.policies.set(policy.id, policy);
      
      // Save policies to disk
      this.savePolicies();
      
      this.emit('policyCreated', {
        id: policy.id,
        name: policy.name
      });
      
      return policy;
    } catch (error) {
      this.emit('error', {
        error: `Error creating policy: ${error.message}`
      });
      
      throw error;
    }
  }

  /**
   * Get a scan policy by ID
   * @param {string} id - Policy ID
   * @returns {Object} - Scan policy
   */
  getPolicy(id) {
    if (!this.policies.has(id)) {
      throw new Error(`Policy with ID ${id} not found`);
    }
    
    return this.policies.get(id);
  }

  /**
   * Update an existing scan policy
   * @param {string} id - Policy ID
   * @param {Object} updates - Policy updates
   * @returns {Object} - Updated policy
   */
  updatePolicy(id, updates) {
    try {
      if (!this.policies.has(id)) {
        throw new Error(`Policy with ID ${id} not found`);
      }
      
      const policy = this.policies.get(id);
      
      // Apply updates
      const updatedPolicy = {
        ...policy,
        ...updates,
        id: policy.id, // Ensure ID doesn't change
        createdAt: policy.createdAt, // Ensure creation timestamp doesn't change
        updatedAt: Date.now() // Update the update timestamp
      };
      
      // Validate updated policy
      this.validatePolicy(updatedPolicy);
      
      // Store updated policy
      this.policies.set(id, updatedPolicy);
      
      // Save policies to disk
      this.savePolicies();
      
      this.emit('policyUpdated', {
        id: updatedPolicy.id,
        name: updatedPolicy.name
      });
      
      return updatedPolicy;
    } catch (error) {
      this.emit('error', {
        error: `Error updating policy: ${error.message}`
      });
      
      throw error;
    }
  }

  /**
   * Delete a scan policy
   * @param {string} id - Policy ID
   * @returns {boolean} - True if policy was deleted
   */
  deletePolicy(id) {
    try {
      if (id === 'default') {
        throw new Error('Cannot delete the default policy');
      }
      
      if (!this.policies.has(id)) {
        throw new Error(`Policy with ID ${id} not found`);
      }
      
      const policy = this.policies.get(id);
      
      // Delete policy
      this.policies.delete(id);
      
      // Save policies to disk
      this.savePolicies();
      
      this.emit('policyDeleted', {
        id: id,
        name: policy.name
      });
      
      return true;
    } catch (error) {
      this.emit('error', {
        error: `Error deleting policy: ${error.message}`
      });
      
      throw error;
    }
  }

  /**
   * List all scan policies
   * @returns {Array} - Array of scan policies
   */
  listPolicies() {
    return Array.from(this.policies.values());
  }

  /**
   * Clone an existing scan policy
   * @param {string} id - Policy ID to clone
   * @param {string} newName - Name for the cloned policy
   * @returns {Object} - Cloned policy
   */
  clonePolicy(id, newName) {
    try {
      if (!this.policies.has(id)) {
        throw new Error(`Policy with ID ${id} not found`);
      }
      
      const policy = this.policies.get(id);
      
      // Create a deep copy of the policy
      const clonedPolicy = JSON.parse(JSON.stringify(policy));
      
      // Update ID, name, and timestamps
      clonedPolicy.id = crypto.randomBytes(8).toString('hex');
      clonedPolicy.name = newName || `${policy.name} (Clone)`;
      clonedPolicy.createdAt = Date.now();
      clonedPolicy.updatedAt = Date.now();
      
      // Store cloned policy
      this.policies.set(clonedPolicy.id, clonedPolicy);
      
      // Save policies to disk
      this.savePolicies();
      
      this.emit('policyCloned', {
        originalId: id,
        newId: clonedPolicy.id,
        name: clonedPolicy.name
      });
      
      return clonedPolicy;
    } catch (error) {
      this.emit('error', {
        error: `Error cloning policy: ${error.message}`
      });
      
      throw error;
    }
  }

  /**
   * Reset a scan policy to default settings
   * @param {string} id - Policy ID
   * @returns {Object} - Reset policy
   */
  resetPolicy(id) {
    try {
      if (!this.policies.has(id)) {
        throw new Error(`Policy with ID ${id} not found`);
      }
      
      const policy = this.policies.get(id);
      
      // Create a deep copy of the default policy
      const resetPolicy = JSON.parse(JSON.stringify(this.defaultPolicy));
      
      // Preserve ID, name, and creation timestamp
      resetPolicy.id = policy.id;
      resetPolicy.name = policy.name;
      resetPolicy.createdAt = policy.createdAt;
      resetPolicy.updatedAt = Date.now();
      
      // Store reset policy
      this.policies.set(id, resetPolicy);
      
      // Save policies to disk
      this.savePolicies();
      
      this.emit('policyReset', {
        id: resetPolicy.id,
        name: resetPolicy.name
      });
      
      return resetPolicy;
    } catch (error) {
      this.emit('error', {
        error: `Error resetting policy: ${error.message}`
      });
      
      throw error;
    }
  }

  /**
   * Create a custom scan policy template
   * @param {string} templateName - Template name
   * @param {string} templateType - Template type (e.g., 'fast', 'thorough', 'passive')
   * @returns {Object} - Created policy template
   */
  createPolicyTemplate(templateName, templateType) {
    try {
      let template;
      
      switch (templateType.toLowerCase()) {
        case 'fast':
          template = this.createFastScanTemplate(templateName);
          break;
        case 'thorough':
          template = this.createThoroughScanTemplate(templateName);
          break;
        case 'passive':
          template = this.createPassiveScanTemplate(templateName);
          break;
        case 'api':
          template = this.createApiScanTemplate(templateName);
          break;
        case 'webapp':
          template = this.createWebAppScanTemplate(templateName);
          break;
        default:
          throw new Error(`Unknown template type: ${templateType}`);
      }
      
      // Store template
      this.policies.set(template.id, template);
      
      // Save policies to disk
      this.savePolicies();
      
      this.emit('templateCreated', {
        id: template.id,
        name: template.name,
        type: templateType
      });
      
      return template;
    } catch (error) {
      this.emit('error', {
        error: `Error creating policy template: ${error.message}`
      });
      
      throw error;
    }
  }

  /**
   * Create a fast scan template
   * @param {string} name - Template name
   * @returns {Object} - Fast scan template
   */
  createFastScanTemplate(name) {
    // Create a deep copy of the default policy
    const template = JSON.parse(JSON.stringify(this.defaultPolicy));
    
    // Update ID, name, and timestamps
    template.id = crypto.randomBytes(8).toString('hex');
    template.name = name || 'Fast Scan Template';
    template.description = 'Optimized for speed with reduced test coverage';
    template.createdAt = Date.now();
    template.updatedAt = Date.now();
    
    // Modify settings for speed
    template.vulnerabilityChecks.sqlInjection.options.payloadLevel = 'low';
    template.vulnerabilityChecks.xss.options.payloadLevel = 'low';
    template.vulnerabilityChecks.ssrf.options.payloadLevel = 'low';
    template.vulnerabilityChecks.xxe.options.payloadLevel = 'low';
    template.vulnerabilityChecks.commandInjection.options.payloadLevel = 'low';
    template.vulnerabilityChecks.fileInclusion.options.payloadLevel = 'low';
    template.vulnerabilityChecks.insecureDeserialization.options.payloadLevel = 'low';
    
    // Disable some checks
    template.vulnerabilityChecks.insecureDeserialization.enabled = false;
    
    // Modify technical options
    template.technicalOptions.intelligentCrawling.options.maxDepth = 2;
    template.technicalOptions.intelligentCrawling.options.maxPages = 50;
    template.technicalOptions.apiEndpointDiscovery.options.maxDepth = 2;
    template.technicalOptions.apiEndpointDiscovery.options.maxPages = 50;
    
    // Increase throttling
    template.scanThrottling.options.requestsPerSecond = 20;
    template.scanThrottling.options.maxConcurrentRequests = 10;
    
    return template;
  }

  /**
   * Create a thorough scan template
   * @param {string} name - Template name
   * @returns {Object} - Thorough scan template
   */
  createThoroughScanTemplate(name) {
    // Create a deep copy of the default policy
    const template = JSON.parse(JSON.stringify(this.defaultPolicy));
    
    // Update ID, name, and timestamps
    template.id = crypto.randomBytes(8).toString('hex');
    template.name = name || 'Thorough Scan Template';
    template.description = 'Comprehensive scan with maximum test coverage';
    template.createdAt = Date.now();
    template.updatedAt = Date.now();
    
    // Modify settings for thoroughness
    template.vulnerabilityChecks.sqlInjection.options.payloadLevel = 'high';
    template.vulnerabilityChecks.xss.options.payloadLevel = 'high';
    template
(Content truncated due to size limit. Use line ranges to read in chunks)
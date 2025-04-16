/**
 * Scanner Core - Main orchestration module for the vulnerability detection engine
 * 
 * This module serves as the central coordinator for all scanning activities,
 * managing the execution flow of various vulnerability detection modules.
 */

const EventEmitter = require('events');

class Scanner extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      concurrency: options.concurrency || 5,
      timeout: options.timeout || 30000,
      throttle: options.throttle || 1000,
      userAgent: options.userAgent || 'SecurScan Pro Security Scanner',
      followRedirects: options.followRedirects !== undefined ? options.followRedirects : true,
      maxDepth: options.maxDepth || 3,
      ...options
    };
    
    this.target = null;
    this.modules = [];
    this.results = [];
    this.status = 'idle';
    this.startTime = null;
    this.endTime = null;
    this.progress = 0;
  }

  /**
   * Register a vulnerability detection module with the scanner
   * @param {Object} module - The vulnerability detection module to register
   */
  registerModule(module) {
    if (!module.name || typeof module.scan !== 'function') {
      throw new Error('Invalid module: must have name and scan method');
    }
    this.modules.push(module);
    return this;
  }

  /**
   * Set the target for scanning
   * @param {string|Object} target - URL or target object with detailed configuration
   */
  setTarget(target) {
    if (typeof target === 'string') {
      this.target = { url: target };
    } else {
      this.target = target;
    }
    return this;
  }

  /**
   * Start the scanning process
   */
  async start() {
    if (!this.target) {
      throw new Error('No target specified');
    }
    
    if (this.modules.length === 0) {
      throw new Error('No scanning modules registered');
    }
    
    this.status = 'running';
    this.startTime = Date.now();
    this.results = [];
    this.progress = 0;
    
    this.emit('scan:start', { target: this.target, timestamp: this.startTime });
    
    try {
      // Run modules sequentially for now
      // In the future, we can implement parallel execution with proper throttling
      for (const module of this.modules) {
        if (this.status !== 'running') break; // Allow for cancellation
        
        this.emit('module:start', { name: module.name, target: this.target });
        
        try {
          const moduleResults = await module.scan(this.target, this.options);
          
          if (moduleResults && moduleResults.length > 0) {
            this.results.push(...moduleResults);
            this.emit('vulnerability:found', moduleResults);
          }
          
          this.emit('module:complete', { 
            name: module.name, 
            vulnerabilitiesFound: moduleResults ? moduleResults.length : 0 
          });
        } catch (error) {
          this.emit('module:error', { 
            name: module.name, 
            error: error.message 
          });
        }
        
        // Update progress
        this.progress = Math.round(((this.modules.indexOf(module) + 1) / this.modules.length) * 100);
        this.emit('scan:progress', { progress: this.progress });
      }
      
      this.endTime = Date.now();
      this.status = 'completed';
      
      this.emit('scan:complete', {
        target: this.target,
        duration: this.endTime - this.startTime,
        vulnerabilitiesFound: this.results.length,
        timestamp: this.endTime
      });
      
      return this.results;
    } catch (error) {
      this.status = 'error';
      this.endTime = Date.now();
      
      this.emit('scan:error', {
        error: error.message,
        target: this.target,
        duration: this.endTime - this.startTime,
        timestamp: this.endTime
      });
      
      throw error;
    }
  }

  /**
   * Stop the scanning process
   */
  stop() {
    if (this.status === 'running') {
      this.status = 'stopped';
      this.endTime = Date.now();
      
      this.emit('scan:stop', {
        target: this.target,
        duration: this.endTime - this.startTime,
        progress: this.progress,
        timestamp: this.endTime
      });
    }
    return this;
  }

  /**
   * Get the current scan results
   */
  getResults() {
    return this.results;
  }

  /**
   * Get the current scan status
   */
  getStatus() {
    return {
      status: this.status,
      progress: this.progress,
      target: this.target,
      startTime: this.startTime,
      endTime: this.endTime,
      duration: this.startTime && (this.endTime || Date.now()) - this.startTime,
      modulesRegistered: this.modules.length,
      vulnerabilitiesFound: this.results.length
    };
  }
}

module.exports = Scanner;

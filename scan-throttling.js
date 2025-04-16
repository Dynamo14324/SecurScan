/**
 * Scan Throttling Module
 * 
 * This module provides functionality for controlling the rate of security scanning
 * to prevent overloading target systems and avoid detection.
 */

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const robotsParser = require('robots-parser');
const axios = require('axios');

class ScanThrottling extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      requestsPerSecond: options.requestsPerSecond || 10,
      maxConcurrentRequests: options.maxConcurrentRequests || 5,
      delayBetweenRequests: options.delayBetweenRequests || 100,
      respectRobotsTxt: options.respectRobotsTxt !== false,
      respectMetaRobots: options.respectMetaRobots !== false,
      logResults: options.logResults !== false,
      logDirectory: options.logDirectory || './logs',
      ...options
    };
    
    // Create log directory if it doesn't exist
    if (this.options.logResults && !fs.existsSync(this.options.logDirectory)) {
      fs.mkdirSync(this.options.logDirectory, { recursive: true });
    }
    
    this.activeRequests = 0;
    this.requestQueue = [];
    this.lastRequestTime = 0;
    this.robotsTxtCache = new Map();
    this.disallowedUrls = new Set();
    this.processingQueue = false;
  }

  /**
   * Schedule a request to be executed with throttling
   * @param {Function} requestFn - Function that returns a Promise for the request
   * @param {string} url - URL of the request
   * @returns {Promise} - Promise that resolves with the request result
   */
  async scheduleRequest(requestFn, url) {
    try {
      // Check if URL is allowed by robots.txt
      if (this.options.respectRobotsTxt && url) {
        const isAllowed = await this.isAllowedByRobotsTxt(url);
        
        if (!isAllowed) {
          this.emit('requestBlocked', {
            url: url,
            reason: 'Blocked by robots.txt'
          });
          
          throw new Error(`URL ${url} is disallowed by robots.txt`);
        }
      }
      
      // Create a promise that will resolve when the request is executed
      return new Promise((resolve, reject) => {
        this.requestQueue.push({
          requestFn,
          url,
          resolve,
          reject,
          timestamp: Date.now()
        });
        
        // Start processing the queue if not already processing
        if (!this.processingQueue) {
          this.processQueue();
        }
      });
    } catch (error) {
      this.emit('error', {
        error: `Error scheduling request: ${error.message}`
      });
      
      throw error;
    }
  }

  /**
   * Process the request queue
   */
  async processQueue() {
    this.processingQueue = true;
    
    while (this.requestQueue.length > 0) {
      // Check if we can execute more requests
      if (this.activeRequests >= this.options.maxConcurrentRequests) {
        // Wait for active requests to decrease
        await new Promise(resolve => setTimeout(resolve, 100));
        continue;
      }
      
      // Check if we need to wait to respect the requests per second limit
      const now = Date.now();
      const timeSinceLastRequest = now - this.lastRequestTime;
      const minRequestInterval = 1000 / this.options.requestsPerSecond;
      
      if (timeSinceLastRequest < minRequestInterval) {
        await new Promise(resolve => setTimeout(resolve, minRequestInterval - timeSinceLastRequest));
        continue;
      }
      
      // Get the next request from the queue
      const request = this.requestQueue.shift();
      
      // Update last request time
      this.lastRequestTime = Date.now();
      
      // Increment active requests counter
      this.activeRequests++;
      
      // Execute the request
      this.executeRequest(request);
    }
    
    this.processingQueue = false;
  }

  /**
   * Execute a request
   * @param {Object} request - Request object
   */
  async executeRequest(request) {
    try {
      // Add delay between requests if specified
      if (this.options.delayBetweenRequests > 0) {
        await new Promise(resolve => setTimeout(resolve, this.options.delayBetweenRequests));
      }
      
      // Execute the request function
      const result = await request.requestFn();
      
      // Resolve the promise with the result
      request.resolve(result);
      
      this.emit('requestCompleted', {
        url: request.url,
        duration: Date.now() - request.timestamp
      });
    } catch (error) {
      // Reject the promise with the error
      request.reject(error);
      
      this.emit('requestFailed', {
        url: request.url,
        error: error.message
      });
    } finally {
      // Decrement active requests counter
      this.activeRequests--;
    }
  }

  /**
   * Check if a URL is allowed by robots.txt
   * @param {string} url - URL to check
   * @returns {Promise<boolean>} - True if URL is allowed
   */
  async isAllowedByRobotsTxt(url) {
    try {
      // Parse the URL
      const parsedUrl = new URL(url);
      const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`;
      const path = parsedUrl.pathname + parsedUrl.search;
      
      // Check if URL is in disallowed cache
      if (this.disallowedUrls.has(url)) {
        return false;
      }
      
      // Check if robots.txt is cached
      if (!this.robotsTxtCache.has(baseUrl)) {
        // Fetch robots.txt
        try {
          const robotsTxtUrl = `${baseUrl}/robots.txt`;
          const response = await axios.get(robotsTxtUrl, {
            timeout: 5000,
            validateStatus: () => true
          });
          
          if (response.status === 200) {
            // Parse robots.txt
            const robotsTxt = robotsParser(robotsTxtUrl, response.data);
            this.robotsTxtCache.set(baseUrl, robotsTxt);
          } else {
            // If robots.txt is not found, assume all URLs are allowed
            this.robotsTxtCache.set(baseUrl, null);
          }
        } catch (error) {
          // If there's an error fetching robots.txt, assume all URLs are allowed
          this.robotsTxtCache.set(baseUrl, null);
        }
      }
      
      // Get robots.txt parser from cache
      const robotsTxt = this.robotsTxtCache.get(baseUrl);
      
      // If robots.txt is not found or couldn't be parsed, assume all URLs are allowed
      if (!robotsTxt) {
        return true;
      }
      
      // Check if URL is allowed
      const isAllowed = robotsTxt.isAllowed(url, 'SecurScan Pro Security Scanner');
      
      // Cache disallowed URLs
      if (!isAllowed) {
        this.disallowedUrls.add(url);
      }
      
      return isAllowed;
    } catch (error) {
      this.emit('error', {
        error: `Error checking robots.txt: ${error.message}`
      });
      
      // If there's an error, assume URL is allowed
      return true;
    }
  }

  /**
   * Check if a URL is allowed by meta robots
   * @param {string} url - URL to check
   * @param {string} html - HTML content of the page
   * @returns {boolean} - True if URL is allowed
   */
  isAllowedByMetaRobots(url, html) {
    try {
      if (!this.options.respectMetaRobots) {
        return true;
      }
      
      // Simple regex to extract meta robots tag
      const metaRobotsRegex = /<meta[^>]*name=["']robots["'][^>]*content=["']([^"']*)["'][^>]*>/i;
      const match = html.match(metaRobotsRegex);
      
      if (!match) {
        return true;
      }
      
      const content = match[1].toLowerCase();
      
      // Check if noindex or none is present
      if (content.includes('noindex') || content.includes('none')) {
        this.emit('requestBlocked', {
          url: url,
          reason: 'Blocked by meta robots tag'
        });
        
        return false;
      }
      
      return true;
    } catch (error) {
      this.emit('error', {
        error: `Error checking meta robots: ${error.message}`
      });
      
      // If there's an error, assume URL is allowed
      return true;
    }
  }

  /**
   * Set the requests per second limit
   * @param {number} requestsPerSecond - Requests per second
   */
  setRequestsPerSecond(requestsPerSecond) {
    this.options.requestsPerSecond = requestsPerSecond;
    
    this.emit('configChanged', {
      option: 'requestsPerSecond',
      value: requestsPerSecond
    });
  }

  /**
   * Set the maximum concurrent requests
   * @param {number} maxConcurrentRequests - Maximum concurrent requests
   */
  setMaxConcurrentRequests(maxConcurrentRequests) {
    this.options.maxConcurrentRequests = maxConcurrentRequests;
    
    this.emit('configChanged', {
      option: 'maxConcurrentRequests',
      value: maxConcurrentRequests
    });
  }

  /**
   * Set the delay between requests
   * @param {number} delayBetweenRequests - Delay between requests in milliseconds
   */
  setDelayBetweenRequests(delayBetweenRequests) {
    this.options.delayBetweenRequests = delayBetweenRequests;
    
    this.emit('configChanged', {
      option: 'delayBetweenRequests',
      value: delayBetweenRequests
    });
  }

  /**
   * Set whether to respect robots.txt
   * @param {boolean} respectRobotsTxt - Whether to respect robots.txt
   */
  setRespectRobotsTxt(respectRobotsTxt) {
    this.options.respectRobotsTxt = respectRobotsTxt;
    
    this.emit('configChanged', {
      option: 'respectRobotsTxt',
      value: respectRobotsTxt
    });
  }

  /**
   * Set whether to respect meta robots
   * @param {boolean} respectMetaRobots - Whether to respect meta robots
   */
  setRespectMetaRobots(respectMetaRobots) {
    this.options.respectMetaRobots = respectMetaRobots;
    
    this.emit('configChanged', {
      option: 'respectMetaRobots',
      value: respectMetaRobots
    });
  }

  /**
   * Get current throttling statistics
   * @returns {Object} - Throttling statistics
   */
  getStatistics() {
    return {
      activeRequests: this.activeRequests,
      queuedRequests: this.requestQueue.length,
      requestsPerSecond: this.options.requestsPerSecond,
      maxConcurrentRequests: this.options.maxConcurrentRequests,
      delayBetweenRequests: this.options.delayBetweenRequests,
      respectRobotsTxt: this.options.respectRobotsTxt,
      respectMetaRobots: this.options.respectMetaRobots,
      disallowedUrlsCount: this.disallowedUrls.size,
      robotsTxtCacheSize: this.robotsTxtCache.size
    };
  }

  /**
   * Clear the robots.txt cache
   */
  clearRobotsTxtCache() {
    this.robotsTxtCache.clear();
    this.disallowedUrls.clear();
    
    this.emit('cacheCleared', {
      cache: 'robotsTxt'
    });
  }

  /**
   * Log throttling statistics
   */
  logStatistics() {
    try {
      if (!this.options.logResults) {
        return;
      }
      
      const logFile = path.join(
        this.options.logDirectory,
        `throttling_stats_${Date.now()}.json`
      );
      
      const stats = this.getStatistics();
      
      fs.writeFileSync(logFile, JSON.stringify(stats, null, 2));
    } catch (error) {
      console.error('Error logging throttling statistics:', error);
    }
  }
}

module.exports = ScanThrottling;

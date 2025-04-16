/**
 * API Endpoint Discovery Module
 * 
 * This module provides functionality for discovering API endpoints in web applications.
 * It can identify API endpoints through various techniques including crawling, traffic analysis,
 * and pattern matching.
 */

const axios = require('axios');
const cheerio = require('cheerio');
const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const url = require('url');

class ApiEndpointDiscovery extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      maxDepth: options.maxDepth || 3,
      maxPages: options.maxPages || 100,
      followRedirects: options.followRedirects !== false,
      timeout: options.timeout || 10000,
      concurrency: options.concurrency || 5,
      userAgent: options.userAgent || 'SecurScan Pro Security Scanner',
      includePatterns: options.includePatterns || [],
      excludePatterns: options.excludePatterns || [],
      apiPatterns: options.apiPatterns || [
        '/api/',
        '/rest/',
        '/graphql',
        '/gql',
        '/v1/',
        '/v2/',
        '/v3/',
        '/service/',
        '/services/',
        '/json/',
        '/ajax/',
        '/xhr/',
        '/rpc'
      ],
      logResults: options.logResults !== false,
      logDirectory: options.logDirectory || './logs',
      ...options
    };
    
    // Create log directory if it doesn't exist
    if (this.options.logResults && !fs.existsSync(this.options.logDirectory)) {
      fs.mkdirSync(this.options.logDirectory, { recursive: true });
    }
    
    this.visited = new Set();
    this.queue = [];
    this.apiEndpoints = [];
    this.running = false;
    this.httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'];
  }

  /**
   * Discover API endpoints starting from a URL
   * @param {string} startUrl - URL to start discovery from
   * @returns {Promise<Array>} - Array of discovered API endpoints
   */
  async discover(startUrl) {
    if (this.running) {
      throw new Error('Discovery is already running');
    }
    
    this.running = true;
    this.visited.clear();
    this.queue = [];
    this.apiEndpoints = [];
    
    try {
      // Parse the start URL
      const parsedUrl = new URL(startUrl);
      const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`;
      
      // Add the start URL to the queue
      this.queue.push({
        url: startUrl,
        depth: 0,
        method: 'GET'
      });
      
      this.emit('discoveryStarted', {
        startUrl: startUrl,
        baseUrl: baseUrl,
        timestamp: Date.now()
      });
      
      // Process the queue
      await this.processQueue(baseUrl);
      
      // Analyze JavaScript files for API endpoints
      await this.analyzeJavaScriptFiles(baseUrl);
      
      // Try common API paths
      await this.tryCommonApiPaths(baseUrl);
      
      // Try API discovery techniques
      await this.discoverGraphQL(baseUrl);
      await this.discoverSwagger(baseUrl);
      await this.discoverOpenAPI(baseUrl);
      
      // Remove duplicates
      this.apiEndpoints = this.removeDuplicateEndpoints(this.apiEndpoints);
      
      // Log results if enabled
      if (this.options.logResults) {
        this.logApiEndpoints(startUrl);
      }
      
      this.emit('discoveryCompleted', {
        startUrl: startUrl,
        endpointsFound: this.apiEndpoints.length,
        timestamp: Date.now()
      });
      
      this.running = false;
      return this.apiEndpoints;
    } catch (error) {
      this.running = false;
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Process the discovery queue
   * @param {string} baseUrl - Base URL of the target
   * @returns {Promise<void>}
   */
  async processQueue(baseUrl) {
    const activePromises = new Set();
    
    while (this.queue.length > 0 && this.apiEndpoints.length < this.options.maxPages) {
      // Process up to concurrency items at once
      while (activePromises.size < this.options.concurrency && this.queue.length > 0) {
        const item = this.queue.shift();
        
        // Skip if already visited
        if (this.visited.has(item.url)) {
          continue;
        }
        
        // Mark as visited
        this.visited.add(item.url);
        
        // Process the item
        const promise = this.processQueueItem(item, baseUrl)
          .catch(error => {
            this.emit('error', {
              url: item.url,
              error: error.message
            });
          })
          .finally(() => {
            activePromises.delete(promise);
          });
        
        activePromises.add(promise);
      }
      
      // Wait for at least one promise to complete
      if (activePromises.size > 0) {
        await Promise.race(Array.from(activePromises));
      }
    }
    
    // Wait for all remaining promises to complete
    if (activePromises.size > 0) {
      await Promise.all(Array.from(activePromises));
    }
  }

  /**
   * Process a single queue item
   * @param {Object} item - Queue item
   * @param {string} baseUrl - Base URL of the target
   * @returns {Promise<void>}
   */
  async processQueueItem(item, baseUrl) {
    try {
      // Skip if exceeding max depth
      if (item.depth > this.options.maxDepth) {
        return;
      }
      
      // Skip if URL doesn't match include patterns
      if (this.options.includePatterns.length > 0 && 
          !this.options.includePatterns.some(pattern => item.url.match(pattern))) {
        return;
      }
      
      // Skip if URL matches exclude patterns
      if (this.options.excludePatterns.length > 0 && 
          this.options.excludePatterns.some(pattern => item.url.match(pattern))) {
        return;
      }
      
      // Check if the URL looks like an API endpoint
      if (this.isApiEndpoint(item.url)) {
        this.addApiEndpoint(item.url, item.method);
      }
      
      // Fetch the URL
      const response = await axios({
        method: item.method,
        url: item.url,
        timeout: this.options.timeout,
        maxRedirects: this.options.followRedirects ? 5 : 0,
        validateStatus: () => true, // Accept all status codes
        headers: {
          'User-Agent': this.options.userAgent,
          'Accept': 'text/html,application/xhtml+xml,application/xml,application/json;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'gzip, deflate'
        }
      });
      
      // Check if the response is JSON
      const contentType = response.headers['content-type'] || '';
      
      if (contentType.includes('application/json')) {
        this.addApiEndpoint(item.url, item.method);
        
        // Try to extract API endpoints from JSON response
        this.extractApiEndpointsFromJson(response.data, baseUrl);
      }
      
      // Check if the response is HTML
      if (contentType.includes('text/html') || contentType.includes('application/xhtml+xml')) {
        // Extract links and add to queue
        const links = this.extractLinksFromHtml(response.data, item.url, baseUrl);
        
        for (const link of links) {
          if (!this.visited.has(link)) {
            this.queue.push({
              url: link,
              depth: item.depth + 1,
              method: 'GET'
            });
          }
        }
        
        // Extract JavaScript files
        const scriptSrcs = this.extractScriptSrcsFromHtml(response.data, item.url, baseUrl);
        
        for (const src of scriptSrcs) {
          if (!this.visited.has(src)) {
            this.queue.push({
              url: src,
              depth: item.depth + 1,
              method: 'GET'
            });
          }
        }
        
        // Extract form actions
        const forms = this.extractFormsFromHtml(response.data, item.url, baseUrl);
        
        for (const form of forms) {
          if (!this.visited.has(form.action)) {
            this.queue.push({
              url: form.action,
              depth: item.depth + 1,
              method: form.method
            });
          }
        }
      }
      
      // Check if the response is JavaScript
      if (contentType.includes('application/javascript') || 
          contentType.includes('text/javascript') || 
          item.url.endsWith('.js')) {
        // Extract API endpoints from JavaScript
        this.extractApiEndpointsFromJavaScript(response.data, baseUrl);
      }
      
      this.emit('pageProcessed', {
        url: item.url,
        statusCode: response.status,
        contentType: contentType,
        depth: item.depth
      });
    } catch (error) {
      this.emit('error', {
        url: item.url,
        error: error.message
      });
    }
  }

  /**
   * Extract links from HTML content
   * @param {string} html - HTML content
   * @param {string} currentUrl - Current URL
   * @param {string} baseUrl - Base URL of the target
   * @returns {Array} - Array of extracted links
   */
  extractLinksFromHtml(html, currentUrl, baseUrl) {
    const links = new Set();
    
    try {
      const $ = cheerio.load(html);
      
      // Extract href attributes from a tags
      $('a').each((i, element) => {
        const href = $(element).attr('href');
        
        if (href) {
          const absoluteUrl = this.resolveUrl(href, currentUrl, baseUrl);
          
          if (absoluteUrl && absoluteUrl.startsWith(baseUrl)) {
            links.add(absoluteUrl);
          }
        }
      });
      
      // Extract data-url attributes
      $('[data-url]').each((i, element) => {
        const dataUrl = $(element).attr('data-url');
        
        if (dataUrl) {
          const absoluteUrl = this.resolveUrl(dataUrl, currentUrl, baseUrl);
          
          if (absoluteUrl && absoluteUrl.startsWith(baseUrl)) {
            links.add(absoluteUrl);
          }
        }
      });
    } catch (error) {
      this.emit('error', {
        url: currentUrl,
        error: `Error extracting links: ${error.message}`
      });
    }
    
    return Array.from(links);
  }

  /**
   * Extract script sources from HTML content
   * @param {string} html - HTML content
   * @param {string} currentUrl - Current URL
   * @param {string} baseUrl - Base URL of the target
   * @returns {Array} - Array of extracted script sources
   */
  extractScriptSrcsFromHtml(html, currentUrl, baseUrl) {
    const scriptSrcs = new Set();
    
    try {
      const $ = cheerio.load(html);
      
      // Extract src attributes from script tags
      $('script').each((i, element) => {
        const src = $(element).attr('src');
        
        if (src) {
          const absoluteUrl = this.resolveUrl(src, currentUrl, baseUrl);
          
          if (absoluteUrl && absoluteUrl.startsWith(baseUrl)) {
            scriptSrcs.add(absoluteUrl);
          }
        }
      });
    } catch (error) {
      this.emit('error', {
        url: currentUrl,
        error: `Error extracting script sources: ${error.message}`
      });
    }
    
    return Array.from(scriptSrcs);
  }

  /**
   * Extract forms from HTML content
   * @param {string} html - HTML content
   * @param {string} currentUrl - Current URL
   * @param {string} baseUrl - Base URL of the target
   * @returns {Array} - Array of extracted forms
   */
  extractFormsFromHtml(html, currentUrl, baseUrl) {
    const forms = [];
    
    try {
      const $ = cheerio.load(html);
      
      // Extract form elements
      $('form').each((i, element) => {
        const action = $(element).attr('action') || currentUrl;
        const method = ($(element).attr('method') || 'GET').toUpperCase();
        
        const absoluteAction = this.resolveUrl(action, currentUrl, baseUrl);
        
        if (absoluteAction && absoluteAction.startsWith(baseUrl)) {
          forms.push({
            action: absoluteAction,
            method: method
          });
        }
      });
    } catch (error) {
      this.emit('error', {
        url: currentUrl,
        error: `Error extracting forms: ${error.message}`
      });
    }
    
    return forms;
  }

  /**
   * Extract API endpoints from JavaScript content
   * @param {string} js - JavaScript content
   * @param {string} baseUrl - Base URL of the target
   */
  extractApiEndpointsFromJavaScript(js, baseUrl) {
    try {
      // Extract URLs from JavaScript
      const urlRegex = /['"`](\/[a-zA-Z0-9_\-\/]+)['"]/g;
      let match;
      
      while ((match = urlRegex.exec(js)) !== null) {
        const path = match[1];
        
        if (this.isApiEndpointPath(path)) {
          const absoluteUrl = new URL(path, baseUrl).toString();
          this.addApiEndpoint(absoluteUrl, 'GET');
        }
      }
      
      // Extract fetch/axios calls
      const fetchRegex = /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g;
      const axiosRegex = /axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g;
      const ajaxRegex = /\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`][^}]*\}\s*\)/g;
      
      while ((match = fetchRegex.exec(js)) !== null) {
        const url = match[1];
        const absoluteUrl = this.resolveUrl(url, baseUrl, baseUrl);
        
        if (absoluteUrl) {
          this.addApiEndpoint(absoluteUrl, 'GET');
        }
      }
      
      while ((match = axiosRegex.exec(js)) !== null) {
        const method = match[1].toUpperCase();
        const url = match[2];
        const absoluteUrl = this.resolveUrl(url, baseUrl, baseUrl);
        
        if (absoluteUrl) {
          this.addApiEndpoint(absoluteUrl, method);
        }
      }
      
      while ((match = ajaxRegex.exec(js)) !== null) {
        const url = match[1];
        const absoluteUrl = this.resolveUrl(url, baseUrl, baseUrl);
        
        if (absoluteUrl) {
          this.addApiEndpoint(absoluteUrl, 'GET');
        }
      }
    } catch (error) {
      this.emit('error', {
        error: `Error extracting API endpoints from JavaScript: ${error.message}`
      });
    }
  }

  /**
   * Extract API endpoints from JSON content
   * @param {Object} json - JSON content
   * @param {string} baseUrl - Base URL of the target
   */
  extractApiEndpointsFromJson(json, baseUrl) {
    try {
      // Convert JSON to string
      const jsonString = JSON.stringify(json);
      
      // Extract URLs from JSON
      const urlRegex = /['"](?:https?:\/\/[^'"]+|\/[a-zA-Z0-9_\-\/]+)['"]/g;
      let match;
      
      while ((match = urlRegex.exec(jsonString)) !== null) {
        const url = match[0].replace(/['"]/g, '');
        const absoluteUrl = this.resolveUrl(url, baseUrl, baseUrl);
        
        if (absoluteUrl && this.isApiEndpoint(absoluteUrl)) {
          this.addApiEndpoint(absoluteUrl, 'GET');
        }
      }
    } catch (error) {
      this.emit('error', {
        error: `Error extracting API endpoints from JSON: ${error.message}`
      });
    }
  }

  /**
   * Analyze JavaScript files for API endpoints
   * @param {string} baseUrl - Base URL of the target
   * @returns {Promise<void>}
   */
  async analyzeJavaScriptFiles(baseUrl) {
    // Get all JavaScript files from visited URLs
    const jsFiles = Array.from(this.visited).filter(url => 
      url.endsWith('.js') || 
      url.includes('.js?') || 
      url.includes('/js/')
    );
    
    for (const jsFile of jsFiles) {
      try {
        const response = await axios({
          method: 'GET',
          url: jsFile,
          timeout: this.options.timeout,
          headers: {
            'User-Agent': this.options.userAgent
          }
        });
        
        if (response.status === 200) {
          this.extractApiEndpointsFromJavaScript(response.data, baseUrl);
        }
      } catch (error) {
        this.emit('error', {
          url: jsFile,
          error: `Error analyzing JavaScript file: ${error.message}`
        });
      }
    }
  }

  /**
   * Try common API paths
   * @param {string} baseUrl - Base URL of the target
(Content truncated due to size limit. Use line ranges to read in chunks)
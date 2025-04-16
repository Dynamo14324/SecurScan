/**
 * Headless Browser Automation Module
 * 
 * This module provides functionality for dynamic testing using headless browser automation.
 * It allows for crawling websites, interacting with pages, and detecting client-side vulnerabilities.
 */

const puppeteer = require('puppeteer');
const EventEmitter = require('events');
const { URL } = require('url');

class HeadlessBrowser extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      headless: true,
      defaultTimeout: 30000,
      defaultNavigationTimeout: 30000,
      userAgent: 'SecurScan Pro Security Scanner',
      viewport: { width: 1366, height: 768 },
      interceptRequests: false,
      blockImages: false,
      blockCss: false,
      blockFonts: false,
      ...options
    };
    
    this.browser = null;
    this.page = null;
    this.isRunning = false;
    this.requestLog = [];
    this.responseLog = [];
    this.consoleLog = [];
  }

  /**
   * Initialize the headless browser
   */
  async initialize() {
    if (this.isRunning) {
      return;
    }
    
    try {
      this.browser = await puppeteer.launch({
        headless: this.options.headless,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-accelerated-2d-canvas',
          '--disable-gpu',
          '--window-size=1366,768'
        ]
      });
      
      this.page = await this.browser.newPage();
      
      // Set viewport
      await this.page.setViewport(this.options.viewport);
      
      // Set user agent
      await this.page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      this.page.setDefaultTimeout(this.options.defaultTimeout);
      this.page.setDefaultNavigationTimeout(this.options.defaultNavigationTimeout);
      
      // Set up request interception if enabled
      if (this.options.interceptRequests) {
        await this.page.setRequestInterception(true);
        
        this.page.on('request', request => {
          const resourceType = request.resourceType();
          
          // Block specified resource types if configured
          if ((this.options.blockImages && resourceType === 'image') ||
              (this.options.blockCss && resourceType === 'stylesheet') ||
              (this.options.blockFonts && resourceType === 'font')) {
            request.abort();
            return;
          }
          
          // Log the request
          this.requestLog.push({
            url: request.url(),
            method: request.method(),
            headers: request.headers(),
            resourceType: resourceType,
            timestamp: Date.now()
          });
          
          request.continue();
        });
      }
      
      // Set up response logging
      this.page.on('response', response => {
        this.responseLog.push({
          url: response.url(),
          status: response.status(),
          headers: response.headers(),
          timestamp: Date.now()
        });
      });
      
      // Set up console logging
      this.page.on('console', message => {
        this.consoleLog.push({
          type: message.type(),
          text: message.text(),
          timestamp: Date.now()
        });
      });
      
      // Set up dialog handling (alerts, confirms, prompts)
      this.page.on('dialog', async dialog => {
        await dialog.dismiss();
      });
      
      this.isRunning = true;
      this.emit('initialized');
    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Navigate to a URL
   * @param {string} url - URL to navigate to
   * @param {Object} options - Navigation options
   * @returns {Object} - Navigation result
   */
  async navigate(url, options = {}) {
    if (!this.isRunning) {
      await this.initialize();
    }
    
    try {
      const navigationOptions = {
        waitUntil: options.waitUntil || 'networkidle2',
        timeout: options.timeout || this.options.defaultNavigationTimeout
      };
      
      // Clear logs before navigation
      if (options.clearLogs !== false) {
        this.clearLogs();
      }
      
      // Navigate to the URL
      const response = await this.page.goto(url, navigationOptions);
      
      // Wait for additional time if specified
      if (options.waitTime) {
        await this.page.waitForTimeout(options.waitTime);
      }
      
      // Get page information
      const pageInfo = await this.getPageInfo();
      
      this.emit('navigation', {
        url: url,
        status: response.status(),
        headers: response.headers(),
        pageInfo: pageInfo
      });
      
      return {
        success: true,
        url: url,
        status: response.status(),
        headers: response.headers(),
        pageInfo: pageInfo
      };
    } catch (error) {
      this.emit('error', error);
      
      return {
        success: false,
        url: url,
        error: error.message
      };
    }
  }

  /**
   * Get information about the current page
   * @returns {Object} - Page information
   */
  async getPageInfo() {
    try {
      const url = await this.page.url();
      const title = await this.page.title();
      
      // Get all links on the page
      const links = await this.page.evaluate(() => {
        return Array.from(document.querySelectorAll('a')).map(a => {
          return {
            href: a.href,
            text: a.textContent.trim(),
            target: a.target
          };
        });
      });
      
      // Get all forms on the page
      const forms = await this.page.evaluate(() => {
        return Array.from(document.querySelectorAll('form')).map(form => {
          return {
            action: form.action,
            method: form.method.toUpperCase() || 'GET',
            inputs: Array.from(form.querySelectorAll('input, select, textarea')).map(input => {
              return {
                name: input.name,
                type: input.type,
                value: input.value,
                id: input.id
              };
            })
          };
        });
      });
      
      // Get all scripts on the page
      const scripts = await this.page.evaluate(() => {
        return Array.from(document.querySelectorAll('script')).map(script => {
          return {
            src: script.src,
            type: script.type,
            content: script.innerText.substring(0, 1000) // Limit content size
          };
        });
      });
      
      // Get all iframes on the page
      const iframes = await this.page.evaluate(() => {
        return Array.from(document.querySelectorAll('iframe')).map(iframe => {
          return {
            src: iframe.src,
            id: iframe.id,
            name: iframe.name
          };
        });
      });
      
      return {
        url: url,
        title: title,
        links: links,
        forms: forms,
        scripts: scripts,
        iframes: iframes
      };
    } catch (error) {
      this.emit('error', error);
      return {};
    }
  }

  /**
   * Fill a form on the page
   * @param {Object} formData - Form data to fill
   * @param {Object} options - Form filling options
   * @returns {Object} - Form filling result
   */
  async fillForm(formData, options = {}) {
    if (!this.isRunning) {
      throw new Error('Browser not initialized');
    }
    
    try {
      const formSelector = options.formSelector || 'form';
      const submitForm = options.submitForm !== false;
      
      // Find the form
      const formExists = await this.page.$(formSelector);
      if (!formExists) {
        throw new Error(`Form not found: ${formSelector}`);
      }
      
      // Fill form fields
      for (const [name, value] of Object.entries(formData)) {
        const selector = `${formSelector} [name="${name}"]`;
        const element = await this.page.$(selector);
        
        if (element) {
          const tagName = await this.page.evaluate(el => el.tagName.toLowerCase(), element);
          const type = await this.page.evaluate(el => el.type, element);
          
          if (tagName === 'select') {
            await this.page.select(selector, value);
          } else if (type === 'checkbox' || type === 'radio') {
            if (value) {
              await this.page.click(selector);
            }
          } else {
            await this.page.type(selector, value);
          }
        }
      }
      
      // Submit the form if requested
      if (submitForm) {
        await this.page.evaluate((selector) => {
          const form = document.querySelector(selector);
          if (form) {
            form.submit();
          }
        }, formSelector);
        
        // Wait for navigation after form submission
        await this.page.waitForNavigation({ waitUntil: 'networkidle2' });
      }
      
      // Get page information after form submission
      const pageInfo = await this.getPageInfo();
      
      this.emit('formSubmitted', {
        formData: formData,
        pageInfo: pageInfo
      });
      
      return {
        success: true,
        formData: formData,
        pageInfo: pageInfo
      };
    } catch (error) {
      this.emit('error', error);
      
      return {
        success: false,
        formData: formData,
        error: error.message
      };
    }
  }

  /**
   * Click on an element on the page
   * @param {string} selector - CSS selector for the element to click
   * @param {Object} options - Click options
   * @returns {Object} - Click result
   */
  async click(selector, options = {}) {
    if (!this.isRunning) {
      throw new Error('Browser not initialized');
    }
    
    try {
      // Check if the element exists
      const elementExists = await this.page.$(selector);
      if (!elementExists) {
        throw new Error(`Element not found: ${selector}`);
      }
      
      // Click the element
      await this.page.click(selector, options);
      
      // Wait for navigation if expected
      if (options.waitForNavigation) {
        await this.page.waitForNavigation({ waitUntil: 'networkidle2' });
      }
      
      // Wait for additional time if specified
      if (options.waitTime) {
        await this.page.waitForTimeout(options.waitTime);
      }
      
      // Get page information after click
      const pageInfo = await this.getPageInfo();
      
      this.emit('elementClicked', {
        selector: selector,
        pageInfo: pageInfo
      });
      
      return {
        success: true,
        selector: selector,
        pageInfo: pageInfo
      };
    } catch (error) {
      this.emit('error', error);
      
      return {
        success: false,
        selector: selector,
        error: error.message
      };
    }
  }

  /**
   * Take a screenshot of the current page
   * @param {Object} options - Screenshot options
   * @returns {Buffer} - Screenshot buffer
   */
  async takeScreenshot(options = {}) {
    if (!this.isRunning) {
      throw new Error('Browser not initialized');
    }
    
    try {
      const screenshotOptions = {
        fullPage: options.fullPage !== false,
        type: options.type || 'png',
        quality: options.quality || 80,
        ...options
      };
      
      const screenshot = await this.page.screenshot(screenshotOptions);
      
      this.emit('screenshotTaken', {
        url: await this.page.url(),
        timestamp: Date.now()
      });
      
      return screenshot;
    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Execute JavaScript code on the page
   * @param {string|Function} script - JavaScript code to execute
   * @param {Array} args - Arguments to pass to the script
   * @returns {*} - Result of the script execution
   */
  async executeScript(script, ...args) {
    if (!this.isRunning) {
      throw new Error('Browser not initialized');
    }
    
    try {
      const result = await this.page.evaluate(script, ...args);
      
      this.emit('scriptExecuted', {
        script: script.toString(),
        timestamp: Date.now()
      });
      
      return result;
    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Crawl a website starting from the current page
   * @param {Object} options - Crawling options
   * @returns {Object} - Crawling results
   */
  async crawl(options = {}) {
    if (!this.isRunning) {
      throw new Error('Browser not initialized');
    }
    
    const crawlOptions = {
      maxDepth: options.maxDepth || 2,
      maxPages: options.maxPages || 20,
      sameDomain: options.sameDomain !== false,
      excludePatterns: options.excludePatterns || [],
      includePatterns: options.includePatterns || [],
      ...options
    };
    
    const visited = new Set();
    const queue = [];
    const results = [];
    
    // Start with the current URL
    const startUrl = await this.page.url();
    const startUrlObj = new URL(startUrl);
    queue.push({ url: startUrl, depth: 0 });
    
    this.emit('crawlStarted', {
      startUrl: startUrl,
      options: crawlOptions
    });
    
    while (queue.length > 0 && results.length < crawlOptions.maxPages) {
      const { url, depth } = queue.shift();
      
      // Skip if already visited
      if (visited.has(url)) {
        continue;
      }
      
      // Skip if exceeding max depth
      if (depth > crawlOptions.maxDepth) {
        continue;
      }
      
      // Skip if URL doesn't match include patterns
      if (crawlOptions.includePatterns.length > 0 && 
          !crawlOptions.includePatterns.some(pattern => url.match(pattern))) {
        continue;
      }
      
      // Skip if URL matches exclude patterns
      if (crawlOptions.excludePatterns.length > 0 && 
          crawlOptions.excludePatterns.some(pattern => url.match(pattern))) {
        continue;
      }
      
      // Skip if not same domain and sameDomain option is true
      if (crawlOptions.sameDomain) {
        const urlObj = new URL(url);
        if (urlObj.hostname !== startUrlObj.hostname) {
          continue;
        }
      }
      
      // Mark as visited
      visited.add(url);
      
      try {
        // Navigate to the URL
        const navigationResult = await this.navigate(url);
        
        if (navigationResult.success) {
          // Add to results
          results.push({
            url: url,
            title: navigationResult.pageInfo.title,
            status: navigationResult.status,
            links: navigationResult.pageInfo.links,
            forms: navigationResult.pageInfo.forms
          });
          
          this.emit('pageCrawled', {
            url: url,
            depth: depth,
            pageCount: results.length
          });
          
          // Add links to queue
          for (const link of navigationResult.pageInfo.links) {
            if (link.href && !visited.has(link.href)) {
              queue.push({ url: link.href, depth: depth + 1 });
            }
          }
        }
      } catch (error) {
        this.emit('error', error);
      }
    }
    
    this.emit('crawlCompleted', {
      pagesVisited: results.length,
      startUrl: startUrl
    });
    
    return {
      startUrl: startUrl,
      pagesVisited: results.length,
      pages: results
    };
  }

  /**
   * Detect client-side vulnerabilities on the current page
   * @param {Object} options - Detection options
   * @returns {Object} - Detection results
   */
  async detectClientSideVulnerabilities(options = {}) {
    if (!this.isRunning) {
      throw new Error('Browser not initialized');
    }
    
    const detectionOptions = {
      checkXss: options.checkXss !== false,
      checkJsLibraries: options.checkJsLibraries !== false,
      checkCsp: options.checkCsp !== false,
      checkCookies: options.checkCookies !== false,
      checkLocalStorage: options.checkLocalStorage !== false,
      checkSessionStorage: options.checkSe
(Content truncated due to size limit. Use line ranges to read in chunks)
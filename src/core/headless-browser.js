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
      checkSessionStorage: options.checkSessionStorage !== false,
      checkPostMessages: options.checkPostMessages !== false,
      ...options
    };
    
    const vulnerabilities = [];
    
    try {
      // Check for vulnerable JavaScript libraries
      if (detectionOptions.checkJsLibraries) {
        const jsLibraries = await this.detectVulnerableJsLibraries();
        vulnerabilities.push(...jsLibraries);
      }
      
      // Check for missing or weak Content Security Policy
      if (detectionOptions.checkCsp) {
        const cspIssues = await this.detectCspIssues();
        vulnerabilities.push(...cspIssues);
      }
      
      // Check for insecure cookies
      if (detectionOptions.checkCookies) {
        const cookieIssues = await this.detectInsecureCookies();
        vulnerabilities.push(...cookieIssues);
      }
      
      // Check for sensitive data in local storage
      if (detectionOptions.checkLocalStorage) {
        const localStorageIssues = await this.detectLocalStorageIssues();
        vulnerabilities.push(...localStorageIssues);
      }
      
      // Check for sensitive data in session storage
      if (detectionOptions.checkSessionStorage) {
        const sessionStorageIssues = await this.detectSessionStorageIssues();
        vulnerabilities.push(...sessionStorageIssues);
      }
      
      // Check for insecure postMessage usage
      if (detectionOptions.checkPostMessages) {
        const postMessageIssues = await this.detectPostMessageIssues();
        vulnerabilities.push(...postMessageIssues);
      }
      
      // Check for DOM-based XSS vulnerabilities
      if (detectionOptions.checkXss) {
        const xssIssues = await this.detectDomXssVulnerabilities();
        vulnerabilities.push(...xssIssues);
      }
      
      this.emit('vulnerabilitiesDetected', {
        url: await this.page.url(),
        vulnerabilitiesFound: vulnerabilities.length,
        vulnerabilities: vulnerabilities
      });
      
      return {
        url: await this.page.url(),
        vulnerabilitiesFound: vulnerabilities.length,
        vulnerabilities: vulnerabilities
      };
    } catch (error) {
      this.emit('error', error);
      
      return {
        url: await this.page.url(),
        vulnerabilitiesFound: 0,
        vulnerabilities: [],
        error: error.message
      };
    }
  }

  /**
   * Detect vulnerable JavaScript libraries on the current page
   * @returns {Array} - Array of vulnerability findings
   */
  async detectVulnerableJsLibraries() {
    const vulnerabilities = [];
    
    try {
      // Get all script sources
      const scripts = await this.page.evaluate(() => {
        return Array.from(document.querySelectorAll('script')).map(script => {
          return {
            src: script.src,
            content: script.innerText.substring(0, 1000) // Limit content size
          };
        });
      });
      
      // Check for known vulnerable libraries
      // This is a simplified version; a real implementation would use a vulnerability database
      const vulnerableLibraries = [
        { name: 'jQuery', pattern: /jquery[.-]([0-9.]+)/i, vulnerableVersions: ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '1.8', '1.9', '1.10', '1.11', '1.12', '2.0', '2.1', '2.2'] },
        { name: 'Angular', pattern: /angular[.-]([0-9.]+)/i, vulnerableVersions: ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6'] },
        { name: 'React', pattern: /react[.-]([0-9.]+)/i, vulnerableVersions: ['0.13', '0.14', '15.0', '15.1', '15.2', '15.3', '15.4', '15.5', '15.6', '16.0'] },
        { name: 'Bootstrap', pattern: /bootstrap[.-]([0-9.]+)/i, vulnerableVersions: ['2.0', '2.1', '2.2', '2.3', '3.0', '3.1', '3.2', '3.3', '4.0'] },
        { name: 'Lodash', pattern: /lodash[.-]([0-9.]+)/i, vulnerableVersions: ['0', '1', '2', '3', '4.0', '4.1', '4.2', '4.3', '4.4', '4.5', '4.6', '4.7', '4.8', '4.9', '4.10', '4.11', '4.12', '4.13', '4.14', '4.15', '4.16'] }
      ];
      
      for (const script of scripts) {
        if (script.src) {
          for (const lib of vulnerableLibraries) {
            const match = script.src.match(lib.pattern);
            if (match && match[1]) {
              const version = match[1];
              if (lib.vulnerableVersions.some(v => version.startsWith(v))) {
                vulnerabilities.push({
                  type: 'vulnerable-js-library',
                  severity: 'medium',
                  confidence: 'high',
                  library: lib.name,
                  version: version,
                  url: script.src,
                  description: `Vulnerable version of ${lib.name} detected: ${version}`,
                  remediation: `Update ${lib.name} to the latest version.`
                });
              }
            }
          }
        }
      }
      
      return vulnerabilities;
    } catch (error) {
      this.emit('error', error);
      return [];
    }
  }

  /**
   * Detect Content Security Policy issues on the current page
   * @returns {Array} - Array of vulnerability findings
   */
  async detectCspIssues() {
    const vulnerabilities = [];
    
    try {
      // Get CSP headers
      const response = await this.page.evaluate(() => {
        return {
          url: window.location.href,
          headers: {}
        };
      });
      
      // Get CSP from response headers
      const headers = this.responseLog.find(r => r.url === response.url)?.headers || {};
      const cspHeader = headers['content-security-policy'] || headers['Content-Security-Policy'];
      
      // Check if CSP is missing
      if (!cspHeader) {
        vulnerabilities.push({
          type: 'missing-csp',
          severity: 'medium',
          confidence: 'high',
          url: response.url,
          description: 'Content Security Policy (CSP) is missing',
          remediation: 'Implement a Content Security Policy to prevent XSS and data injection attacks.'
        });
        return vulnerabilities;
      }
      
      // Check for unsafe CSP directives
      const unsafeDirectives = [
        { pattern: /script-src[^;]*'unsafe-inline'/, description: 'CSP allows unsafe inline scripts' },
        { pattern: /script-src[^;]*'unsafe-eval'/, description: 'CSP allows unsafe eval scripts' },
        { pattern: /script-src[^;]*\*/, description: 'CSP allows scripts from any source' },
        { pattern: /object-src[^;]*\*/, description: 'CSP allows objects from any source' },
        { pattern: /frame-src[^;]*\*/, description: 'CSP allows frames from any source' },
        { pattern: /frame-ancestors[^;]*\*/, description: 'CSP allows frame ancestors from any source' }
      ];
      
      for (const directive of unsafeDirectives) {
        if (directive.pattern.test(cspHeader)) {
          vulnerabilities.push({
            type: 'unsafe-csp',
            severity: 'medium',
            confidence: 'high',
            url: response.url,
            csp: cspHeader,
            description: directive.description,
            remediation: 'Strengthen the Content Security Policy by removing unsafe directives and using more restrictive policies.'
          });
        }
      }
      
      return vulnerabilities;
    } catch (error) {
      this.emit('error', error);
      return [];
    }
  }

  /**
   * Detect insecure cookies on the current page
   * @returns {Array} - Array of vulnerability findings
   */
  async detectInsecureCookies() {
    const vulnerabilities = [];
    
    try {
      // Get all cookies
      const cookies = await this.page.cookies();
      
      for (const cookie of cookies) {
        // Check for missing Secure flag
        if (!cookie.secure && (cookie.name.toLowerCase().includes('session') || 
                              cookie.name.toLowerCase().includes('auth') || 
                              cookie.name.toLowerCase().includes('token') || 
                              cookie.name.toLowerCase().includes('jwt'))) {
          vulnerabilities.push({
            type: 'insecure-cookie',
            severity: 'medium',
            confidence: 'high',
            cookie: cookie.name,
            description: `Cookie '${cookie.name}' is missing the Secure flag`,
            remediation: 'Set the Secure flag for all sensitive cookies to ensure they are only transmitted over HTTPS.'
          });
        }
        
        // Check for missing HttpOnly flag
        if (!cookie.httpOnly && (cookie.name.toLowerCase().includes('session') || 
                                cookie.name.toLowerCase().includes('auth') || 
                                cookie.name.toLowerCase().includes('token') || 
                                cookie.name.toLowerCase().includes('jwt'))) {
          vulnerabilities.push({
            type: 'insecure-cookie',
            severity: 'medium',
            confidence: 'high',
            cookie: cookie.name,
            description: `Cookie '${cookie.name}' is missing the HttpOnly flag`,
            remediation: 'Set the HttpOnly flag for all sensitive cookies to prevent access from JavaScript.'
          });
        }
        
        // Check for missing SameSite attribute
        if (!cookie.sameSite && (cookie.name.toLowerCase().includes('session') || 
                                cookie.name.toLowerCase().includes('auth') || 
                                cookie.name.toLowerCase().includes('token') || 
                                cookie.name.toLowerCase().includes('jwt'))) {
          vulnerabilities.push({
            type: 'insecure-cookie',
            severity: 'low',
            confidence: 'high',
            cookie: cookie.name,
            description: `Cookie '${cookie.name}' is missing the SameSite attribute`,
            remediation: 'Set the SameSite attribute to "Lax" or "Strict" for all sensitive cookies to prevent CSRF attacks.'
          });
        }
      }
      
      return vulnerabilities;
    } catch (error) {
      this.emit('error', error);
      return [];
    }
  }

  /**
   * Detect issues with data stored in localStorage
   * @returns {Array} - Array of vulnerability findings
   */
  async detectLocalStorageIssues() {
    const vulnerabilities = [];
    
    try {
      // Get all localStorage items
      const localStorage = await this.page.evaluate(() => {
        const items = {};
        for (let i = 0; i < window.localStorage.length; i++) {
          const key = window.localStorage.key(i);
          items[key] = window.localStorage.getItem(key);
        }
        return items;
      });
      
      // Check for sensitive data in localStorage
      const sensitivePatterns = [
        { pattern: /password/i, description: 'Password found in localStorage' },
        { pattern: /token/i, description: 'Token found in localStorage' },
        { pattern: /jwt/i, description: 'JWT found in localStorage' },
        { pattern: /auth/i, description: 'Authentication data found in localStorage' },
        { pattern: /session/i, description: 'Session data found in localStorage' },
        { pattern: /credit_?card/i, description: 'Credit card data found in localStorage' },
        { pattern: /card_?number/i, description: 'Card number found in localStorage' },
        { pattern: /ssn/i, description: 'Social Security Number found in localStorage' },
        { pattern: /social_?security/i, description: 'Social Security data found in localStorage' },
        { pattern: /passport/i, description: 'Passport data found in localStorage' },
        { pattern: /driver_?licen[sc]e/i, description: 'Driver\'s license data found in localStorage' },
        { pattern: /api_?key/i, description: 'API key found in localStorage' }
      ];
      
      for (const [key, value] of Object.entries(localStorage)) {
        for (const pattern of sensitivePatterns) {
          if (pattern.pattern.test(key) || pattern.pattern.test(value)) {
            vulnerabilities.push({
              type: 'sensitive-data-exposure',
              severity: 'medium',
              confidence: 'medium',
              storage: 'localStorage',
              key: key,
              description: pattern.description,
              remediation: 'Avoid storing sensitive data in localStorage. Use secure storage mechanisms like HttpOnly cookies for sensitive data.'
            });
            break;
          }
        }
      }
      
      return vulnerabilities;
    } catch (error) {
      this.emit('error', error);
      return [];
    }
  }

  /**
   * Detect issues with data stored in sessionStorage
   * @returns {Array} - Array of vulnerability findings
   */
  async detectSessionStorageIssues() {
    const vulnerabilities = [];
    
    try {
      // Get all sessionStorage items
      const sessionStorage = await this.page.evaluate(() => {
        const items = {};
        for (let i = 0; i < window.sessionStorage.length; i++) {
          const key = window.sessionStorage.key(i);
          items[key] = window.sessionStorage.getItem(key);
        }
        return items;
      });
      
      // Check for sensitive data in sessionStorage
      const sensitivePatterns = [
        { pattern: /password/i, description: 'Password found in sessionStorage' },
        { pattern: /token/i, description: 'Token found in sessionStorage' },
        { pattern: /jwt/i, description: 'JWT found in sessionStorage' },
        { pattern: /auth/i, description: 'Authentication data found in sessionStorage' },
        { pattern: /session/i, description: 'Session data found in sessionStorage' },
        { pattern: /credit_?card/i, description: 'Credit card data found in sessionStorage' },
        { pattern: /card_?number/i, description: 'Card number found in sessionStorage' },
        { pattern: /ssn/i, description: 'Social Security Number found in sessionStorage' },
        { pattern: /social_?security/i, description: 'Social Security data found in sessionStorage' },
        { pattern: /passport/i, description: 'Passport data found in sessionStorage' },
        { pattern: /driver_?licen[sc]e/i, description: 'Driver\'s license data found in sessionStorage' },
        { pattern: /api_?key/i, description: 'API key found in sessionStorage' }
      ];
      
      for (const [key, value] of Object.entries(sessionStorage)) {
        for (const pattern of sensitivePatterns) {
          if (pattern.pattern.test(key) || pattern.pattern.test(value)) {
            vulnerabilities.push({
              type: 'sensitive-data-exposure',
              severity: 'medium',
              confidence: 'medium',
              storage: 'sessionStorage',
              key: key,
              description: pattern.description,
              remediation: 'Avoid storing sensitive data in sessionStorage. Use secure storage mechanisms like HttpOnly cookies for sensitive data.'
            });
            break;
          }
        }
      }
      
      return vulnerabilities;
    } catch (error) {
      this.emit('error', error);
      return [];
    }
  }

  /**
   * Detect issues with postMessage usage
   * @returns {Array} - Array of vulnerability findings
   */
  async detectPostMessageIssues() {
    const vulnerabilities = [];
    
    try {
      // Inject script to monitor postMessage usage
      await this.page.evaluate(() => {
        window._postMessageMonitor = {
          messages: [],
          listeners: []
        };
        
        // Monitor incoming messages
        const originalAddEventListener = window.addEventListener;
        window.addEventListener = function(type, listener, options) {
          if (type === 'message') {
            window._postMessageMonitor.listeners.push({
              listener: listener.toString(),
              hasOriginCheck: listener.toString().includes('origin')
            });
          }
          return originalAddEventListener.call(this, type, listener, options);
        };
        
        // Monitor outgoing messages
        const originalPostMessage = window.postMessage;
        window.postMessage = function(message, targetOrigin, transfer) {
          window._postMessageMonitor.messages.push({
            message: JSON.stringify(message),
            targetOrigin: targetOrigin
          });
          return originalPostMessage.call(this, message, targetOrigin, transfer);
        };
      });
      
      // Interact with the page to trigger postMessage events
      await this.page.evaluate(() => {
        // Trigger some common interactions that might use postMessage
        const links = document.querySelectorAll('a');
        for (let i = 0; i < Math.min(links.length, 5); i++) {
          links[i].click();
        }
        
        const buttons = document.querySelectorAll('button');
        for (let i = 0; i < Math.min(buttons.length, 5); i++) {
          buttons[i].click();
        }
      });
      
      // Wait a bit for postMessage events to occur
      await this.page.waitForTimeout(2000);
      
      // Get postMessage monitoring results
      const postMessageResults = await this.page.evaluate(() => {
        return window._postMessageMonitor;
      });
      
      // Check for insecure postMessage listeners
      for (const listener of postMessageResults.listeners) {
        if (!listener.hasOriginCheck) {
          vulnerabilities.push({
            type: 'insecure-postmessage',
            severity: 'medium',
            confidence: 'medium',
            description: 'postMessage event listener does not validate origin',
            evidence: listener.listener.substring(0, 200),
            remediation: 'Always validate the origin of incoming messages in postMessage event listeners.'
          });
        }
      }
      
      // Check for insecure postMessage sending
      for (const message of postMessageResults.messages) {
        if (message.targetOrigin === '*') {
          vulnerabilities.push({
            type: 'insecure-postmessage',
            severity: 'medium',
            confidence: 'high',
            description: 'postMessage is sent with wildcard (*) target origin',
            evidence: `message: ${message.message}, targetOrigin: ${message.targetOrigin}`,
            remediation: 'Specify a concrete target origin instead of using the wildcard (*) when sending messages with postMessage.'
          });
        }
      }
      
      return vulnerabilities;
    } catch (error) {
      this.emit('error', error);
      return [];
    }
  }

  /**
   * Detect DOM-based XSS vulnerabilities
   * @returns {Array} - Array of vulnerability findings
   */
  async detectDomXssVulnerabilities() {
    const vulnerabilities = [];
    
    try {
      // Inject script to monitor DOM sinks
      await this.page.evaluate(() => {
        window._domXssMonitor = {
          sinks: []
        };
        
        // Monitor common DOM XSS sinks
        const sinks = [
          'document.write',
          'document.writeln',
          'document.body.innerHTML',
          'document.body.outerHTML',
          'document.createElement',
          'element.innerHTML',
          'element.outerHTML',
          'element.setAttribute',
          'element.insertAdjacentHTML',
          'eval',
          'setTimeout',
          'setInterval',
          'location',
          'location.href',
          'location.replace',
          'location.assign',
          'jQuery.html'
        ];
        
        // Helper function to get the path to an object property
        function getPath(obj, path) {
          const parts = path.split('.');
          let current = obj;
          
          for (let i = 0; i < parts.length; i++) {
            if (current === undefined || current === null) {
              return undefined;
            }
            current = current[parts[i]];
          }
          
          return current;
        }
        
        // Helper function to set the path to an object property
        function setPath(obj, path, value) {
          const parts = path.split('.');
          let current = obj;
          
          for (let i = 0; i < parts.length - 1; i++) {
            if (current[parts[i]] === undefined) {
              current[parts[i]] = {};
            }
            current = current[parts[i]];
          }
          
          const originalFunction = current[parts[parts.length - 1]];
          current[parts[parts.length - 1]] = function() {
            window._domXssMonitor.sinks.push({
              sink: path,
              args: Array.from(arguments).map(arg => String(arg)),
              stack: new Error().stack
            });
            return originalFunction.apply(this, arguments);
          };
        }
        
        // Monitor document sinks
        setPath(window, 'document.write', document.write);
        setPath(window, 'document.writeln', document.writeln);
        
        // Monitor eval
        setPath(window, 'eval', eval);
        
        // Monitor setTimeout and setInterval
        setPath(window, 'setTimeout', setTimeout);
        setPath(window, 'setInterval', setInterval);
        
        // Monitor location
        const originalLocation = window.location;
        Object.defineProperty(window, 'location', {
          get: function() {
            return originalLocation;
          },
          set: function(value) {
            window._domXssMonitor.sinks.push({
              sink: 'location',
              args: [String(value)],
              stack: new Error().stack
            });
            originalLocation.href = value;
          }
        });
        
        // Monitor innerHTML and outerHTML for all elements
        const originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        const originalOuterHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
        
        Object.defineProperty(Element.prototype, 'innerHTML', {
          get: function() {
            return originalInnerHTMLDescriptor.get.call(this);
          },
          set: function(value) {
            window._domXssMonitor.sinks.push({
              sink: 'innerHTML',
              element: this.tagName,
              args: [String(value)],
              stack: new Error().stack
            });
            return originalInnerHTMLDescriptor.set.call(this, value);
          }
        });
        
        Object.defineProperty(Element.prototype, 'outerHTML', {
          get: function() {
            return originalOuterHTMLDescriptor.get.call(this);
          },
          set: function(value) {
            window._domXssMonitor.sinks.push({
              sink: 'outerHTML',
              element: this.tagName,
              args: [String(value)],
              stack: new Error().stack
            });
            return originalOuterHTMLDescriptor.set.call(this, value);
          }
        });
        
        // Monitor insertAdjacentHTML
        const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
        Element.prototype.insertAdjacentHTML = function(position, text) {
          window._domXssMonitor.sinks.push({
            sink: 'insertAdjacentHTML',
            element: this.tagName,
            args: [position, text],
            stack: new Error().stack
          });
          return originalInsertAdjacentHTML.call(this, position, text);
        };
        
        // Monitor setAttribute
        const originalSetAttribute = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function(name, value) {
          window._domXssMonitor.sinks.push({
            sink: 'setAttribute',
            element: this.tagName,
            args: [name, value],
            stack: new Error().stack
          });
          return originalSetAttribute.call(this, name, value);
        };
        
        // Monitor jQuery.html if jQuery is available
        if (window.jQuery) {
          const originalJQueryHtml = window.jQuery.fn.html;
          window.jQuery.fn.html = function(value) {
            if (value !== undefined) {
              window._domXssMonitor.sinks.push({
                sink: 'jQuery.html',
                args: [String(value)],
                stack: new Error().stack
              });
            }
            return originalJQueryHtml.apply(this, arguments);
          };
        }
      });
      
      // Interact with the page to trigger potential DOM XSS
      await this.page.evaluate(() => {
        // Try to trigger DOM XSS by manipulating URL parameters
        const url = new URL(window.location.href);
        
        // Add some common XSS payloads to URL parameters
        const xssPayloads = [
          '<img src=x onerror=console.log("XSS")>',
          '<script>console.log("XSS")</script>',
          '"><img src=x onerror=console.log("XSS")>',
          "javascript:console.log('XSS')"
        ];
        
        // Add payloads to existing parameters
        for (const [key, value] of url.searchParams.entries()) {
          for (const payload of xssPayloads) {
            url.searchParams.set(key, payload);
            history.pushState({}, '', url.toString());
            
            // Trigger some common interactions
            document.body.click();
            window.dispatchEvent(new Event('hashchange'));
            window.dispatchEvent(new Event('popstate'));
          }
        }
        
        // Add new parameters with payloads
        for (const payload of xssPayloads) {
          url.searchParams.set('xss', payload);
          history.pushState({}, '', url.toString());
          
          // Trigger some common interactions
          document.body.click();
          window.dispatchEvent(new Event('hashchange'));
          window.dispatchEvent(new Event('popstate'));
        }
      });
      
      // Wait a bit for DOM XSS to be triggered
      await this.page.waitForTimeout(2000);
      
      // Get DOM XSS monitoring results
      const domXssResults = await this.page.evaluate(() => {
        return window._domXssMonitor;
      });
      
      // Check for potential DOM XSS vulnerabilities
      for (const sink of domXssResults.sinks) {
        // Check if any argument contains user input from URL
        const url = new URL(window.location.href);
        const urlParams = Array.from(url.searchParams.entries()).map(([key, value]) => value);
        
        let isVulnerable = false;
        let vulnerableParam = '';
        
        for (const arg of sink.args) {
          for (const param of urlParams) {
            if (arg.includes(param)) {
              isVulnerable = true;
              vulnerableParam = param;
              break;
            }
          }
          
          if (isVulnerable) {
            break;
          }
        }
        
        if (isVulnerable) {
          vulnerabilities.push({
            type: 'dom-xss',
            severity: 'high',
            confidence: 'medium',
            sink: sink.sink,
            element: sink.element,
            parameter: vulnerableParam,
            evidence: JSON.stringify(sink),
            description: `DOM-based XSS vulnerability detected in ${sink.sink}`,
            remediation: 'Sanitize user input before using it in DOM manipulation functions. Use safe DOM APIs like textContent instead of innerHTML.'
          });
        }
      }
      
      return vulnerabilities;
    } catch (error) {
      this.emit('error', error);
      return [];
    }
  }

  /**
   * Clear request, response, and console logs
   */
  clearLogs() {
    this.requestLog = [];
    this.responseLog = [];
    this.consoleLog = [];
  }

  /**
   * Get request logs
   * @param {Object} options - Options for filtering logs
   * @returns {Array} - Array of request logs
   */
  getRequestLogs(options = {}) {
    let logs = [...this.requestLog];
    
    // Filter by URL
    if (options.url) {
      logs = logs.filter(log => log.url.includes(options.url));
    }
    
    // Filter by method
    if (options.method) {
      logs = logs.filter(log => log.method === options.method);
    }
    
    // Filter by resource type
    if (options.resourceType) {
      logs = logs.filter(log => log.resourceType === options.resourceType);
    }
    
    // Limit number of logs
    if (options.limit) {
      logs = logs.slice(0, options.limit);
    }
    
    return logs;
  }

  /**
   * Get response logs
   * @param {Object} options - Options for filtering logs
   * @returns {Array} - Array of response logs
   */
  getResponseLogs(options = {}) {
    let logs = [...this.responseLog];
    
    // Filter by URL
    if (options.url) {
      logs = logs.filter(log => log.url.includes(options.url));
    }
    
    // Filter by status
    if (options.status) {
      logs = logs.filter(log => log.status === options.status);
    }
    
    // Limit number of logs
    if (options.limit) {
      logs = logs.slice(0, options.limit);
    }
    
    return logs;
  }

  /**
   * Get console logs
   * @param {Object} options - Options for filtering logs
   * @returns {Array} - Array of console logs
   */
  getConsoleLogs(options = {}) {
    let logs = [...this.consoleLog];
    
    // Filter by type
    if (options.type) {
      logs = logs.filter(log => log.type === options.type);
    }
    
    // Filter by text
    if (options.text) {
      logs = logs.filter(log => log.text.includes(options.text));
    }
    
    // Limit number of logs
    if (options.limit) {
      logs = logs.slice(0, options.limit);
    }
    
    return logs;
  }

  /**
   * Close the browser
   */
  async close() {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.page = null;
      this.isRunning = false;
      this.clearLogs();
      
      this.emit('closed');
    }
  }
}

module.exports = HeadlessBrowser;

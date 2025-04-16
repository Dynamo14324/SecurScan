/**
 * Intelligent Crawler Module
 * 
 * This module provides functionality for intelligently crawling websites to discover content,
 * functionality, and potential security vulnerabilities.
 */

const puppeteer = require('puppeteer');
const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { v4: uuidv4 } = require('uuid');

class IntelligentCrawler extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      maxDepth: options.maxDepth || 3,
      maxPages: options.maxPages || 100,
      maxConcurrency: options.maxConcurrency || 5,
      timeout: options.timeout || 30000,
      waitTime: options.waitTime || 1000,
      userAgent: options.userAgent || 'SecurScan Pro Security Scanner',
      viewport: options.viewport || { width: 1366, height: 768 },
      ignoreRobotsTxt: options.ignoreRobotsTxt !== false,
      followRedirects: options.followRedirects !== false,
      includePatterns: options.includePatterns || [],
      excludePatterns: options.excludePatterns || [
        /\.(jpg|jpeg|png|gif|webp|svg|ico|css|less|scss|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|tar|gz|mp3|mp4|avi|mov|wmv)$/i
      ],
      clickElements: options.clickElements !== false,
      fillForms: options.fillForms !== false,
      handleAuthentication: options.handleAuthentication !== false,
      credentials: options.credentials || null,
      logResults: options.logResults !== false,
      logDirectory: options.logDirectory || './logs',
      screenshotDirectory: options.screenshotDirectory || './screenshots',
      throttle: options.throttle || {
        enabled: true,
        requestsPerSecond: 2
      },
      ...options
    };
    
    // Create log directory if it doesn't exist
    if (this.options.logResults && !fs.existsSync(this.options.logDirectory)) {
      fs.mkdirSync(this.options.logDirectory, { recursive: true });
    }
    
    // Create screenshot directory if it doesn't exist
    if (!fs.existsSync(this.options.screenshotDirectory)) {
      fs.mkdirSync(this.options.screenshotDirectory, { recursive: true });
    }
    
    this.browser = null;
    this.pages = new Map();
    this.visited = new Set();
    this.queue = [];
    this.results = [];
    this.running = false;
    this.activeCrawls = 0;
    this.lastRequestTime = 0;
  }

  /**
   * Initialize the crawler
   * @returns {Promise<void>}
   */
  async initialize() {
    if (this.browser) {
      return;
    }
    
    try {
      this.browser = await puppeteer.launch({
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-accelerated-2d-canvas',
          '--disable-gpu',
          '--window-size=1366,768'
        ]
      });
      
      this.emit('initialized');
    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Start crawling from a URL
   * @param {string} startUrl - URL to start crawling from
   * @returns {Promise<Object>} - Crawl results
   */
  async crawl(startUrl) {
    if (this.running) {
      throw new Error('Crawler is already running');
    }
    
    this.running = true;
    this.visited.clear();
    this.queue = [];
    this.results = [];
    this.activeCrawls = 0;
    
    try {
      // Initialize browser if not already initialized
      await this.initialize();
      
      // Parse the start URL
      const parsedUrl = new URL(startUrl);
      const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`;
      
      // Add the start URL to the queue
      this.queue.push({
        url: startUrl,
        depth: 0,
        referrer: null,
        reason: 'initial'
      });
      
      this.emit('crawlStarted', {
        startUrl: startUrl,
        baseUrl: baseUrl,
        timestamp: Date.now()
      });
      
      // Process the queue
      await this.processQueue(baseUrl);
      
      // Generate crawl report
      const report = this.generateCrawlReport(startUrl);
      
      // Log results if enabled
      if (this.options.logResults) {
        this.logCrawlResults(report);
      }
      
      this.emit('crawlCompleted', {
        startUrl: startUrl,
        pagesVisited: this.results.length,
        timestamp: Date.now()
      });
      
      this.running = false;
      return report;
    } catch (error) {
      this.running = false;
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Process the crawl queue
   * @param {string} baseUrl - Base URL of the target
   * @returns {Promise<void>}
   */
  async processQueue(baseUrl) {
    while (this.queue.length > 0 && this.results.length < this.options.maxPages) {
      // Process up to maxConcurrency items at once
      while (this.activeCrawls < this.options.maxConcurrency && this.queue.length > 0) {
        const item = this.queue.shift();
        
        // Skip if already visited
        if (this.visited.has(item.url)) {
          continue;
        }
        
        // Mark as visited
        this.visited.add(item.url);
        
        // Throttle requests if enabled
        if (this.options.throttle.enabled) {
          const now = Date.now();
          const timeSinceLastRequest = now - this.lastRequestTime;
          const minRequestInterval = 1000 / this.options.throttle.requestsPerSecond;
          
          if (timeSinceLastRequest < minRequestInterval) {
            await new Promise(resolve => setTimeout(resolve, minRequestInterval - timeSinceLastRequest));
          }
          
          this.lastRequestTime = Date.now();
        }
        
        // Process the item
        this.activeCrawls++;
        this.processCrawlItem(item, baseUrl)
          .catch(error => {
            this.emit('error', {
              url: item.url,
              error: error.message
            });
          })
          .finally(() => {
            this.activeCrawls--;
          });
      }
      
      // Wait a bit before checking again
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    // Wait for all active crawls to complete
    while (this.activeCrawls > 0) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  /**
   * Process a single crawl queue item
   * @param {Object} item - Queue item
   * @param {string} baseUrl - Base URL of the target
   * @returns {Promise<void>}
   */
  async processCrawlItem(item, baseUrl) {
    const pageId = uuidv4();
    
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
      
      // Create a new page
      const page = await this.browser.newPage();
      this.pages.set(pageId, page);
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Handle authentication if needed
      if (this.options.handleAuthentication && this.options.credentials) {
        await page.authenticate(this.options.credentials);
      }
      
      // Set up request interception
      await page.setRequestInterception(true);
      
      page.on('request', request => {
        // Skip unnecessary resources
        const resourceType = request.resourceType();
        if (resourceType === 'image' || resourceType === 'font' || resourceType === 'media') {
          request.abort();
          return;
        }
        
        // Continue with the request
        request.continue();
      });
      
      // Navigate to the URL
      const response = await page.goto(item.url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Wait for additional time if specified
      if (this.options.waitTime > 0) {
        await page.waitForTimeout(this.options.waitTime);
      }
      
      // Take a screenshot
      const screenshotPath = path.join(
        this.options.screenshotDirectory,
        `page_${Date.now()}.png`
      );
      
      await page.screenshot({
        path: screenshotPath,
        fullPage: true
      });
      
      // Extract page information
      const pageInfo = await this.extractPageInfo(page, item.url);
      
      // Add to results
      this.results.push({
        url: item.url,
        depth: item.depth,
        referrer: item.referrer,
        reason: item.reason,
        status: response.status(),
        contentType: response.headers()['content-type'] || '',
        title: pageInfo.title,
        headers: response.headers(),
        links: pageInfo.links,
        forms: pageInfo.forms,
        scripts: pageInfo.scripts,
        screenshot: screenshotPath,
        timestamp: Date.now()
      });
      
      this.emit('pageVisited', {
        url: item.url,
        depth: item.depth,
        status: response.status(),
        title: pageInfo.title,
        linksFound: pageInfo.links.length
      });
      
      // Interact with the page if enabled
      if (this.options.clickElements) {
        await this.interactWithPage(page, item.url, item.depth, baseUrl);
      }
      
      // Fill forms if enabled
      if (this.options.fillForms) {
        await this.fillPageForms(page, item.url, item.depth, baseUrl);
      }
      
      // Add links to queue
      for (const link of pageInfo.links) {
        if (!this.visited.has(link.url)) {
          this.queue.push({
            url: link.url,
            depth: item.depth + 1,
            referrer: item.url,
            reason: 'link'
          });
        }
      }
      
      // Close the page
      await page.close();
      this.pages.delete(pageId);
    } catch (error) {
      this.emit('error', {
        url: item.url,
        error: error.message
      });
      
      // Close the page if it exists
      if (this.pages.has(pageId)) {
        await this.pages.get(pageId).close();
        this.pages.delete(pageId);
      }
    }
  }

  /**
   * Extract information from a page
   * @param {Object} page - Puppeteer page object
   * @param {string} currentUrl - Current URL
   * @returns {Promise<Object>} - Page information
   */
  async extractPageInfo(page, currentUrl) {
    try {
      // Get page title
      const title = await page.title();
      
      // Extract links
      const links = await page.evaluate((baseUrl) => {
        const results = [];
        const anchors = document.querySelectorAll('a');
        
        for (const anchor of anchors) {
          if (anchor.href && anchor.href.startsWith('http')) {
            results.push({
              url: anchor.href,
              text: anchor.textContent.trim(),
              target: anchor.target
            });
          }
        }
        
        return results;
      }, currentUrl);
      
      // Extract forms
      const forms = await page.evaluate(() => {
        const results = [];
        const formElements = document.querySelectorAll('form');
        
        for (const form of formElements) {
          const inputs = [];
          const formInputs = form.querySelectorAll('input, select, textarea');
          
          for (const input of formInputs) {
            inputs.push({
              name: input.name,
              type: input.type || 'text',
              value: input.value,
              required: input.required
            });
          }
          
          results.push({
            action: form.action,
            method: form.method.toUpperCase() || 'GET',
            inputs: inputs
          });
        }
        
        return results;
      });
      
      // Extract scripts
      const scripts = await page.evaluate(() => {
        const results = [];
        const scriptElements = document.querySelectorAll('script');
        
        for (const script of scriptElements) {
          results.push({
            src: script.src,
            type: script.type,
            content: script.innerText.substring(0, 1000) // Limit content size
          });
        }
        
        return results;
      });
      
      return {
        title: title,
        links: links,
        forms: forms,
        scripts: scripts
      };
    } catch (error) {
      this.emit('error', {
        url: currentUrl,
        error: `Error extracting page info: ${error.message}`
      });
      
      return {
        title: '',
        links: [],
        forms: [],
        scripts: []
      };
    }
  }

  /**
   * Interact with elements on a page
   * @param {Object} page - Puppeteer page object
   * @param {string} currentUrl - Current URL
   * @param {number} depth - Current depth
   * @param {string} baseUrl - Base URL of the target
   * @returns {Promise<void>}
   */
  async interactWithPage(page, currentUrl, depth, baseUrl) {
    try {
      // Find clickable elements
      const clickableElements = await page.evaluate(() => {
        const results = [];
        
        // Buttons
        const buttons = document.querySelectorAll('button, input[type="button"], input[type="submit"]');
        for (const button of buttons) {
          if (button.offsetParent !== null) { // Check if visible
            results.push({
              type: 'button',
              text: button.textContent || button.value,
              id: button.id,
              selector: button.tagName.toLowerCase() + (button.id ? `#${button.id}` : '')
            });
          }
        }
        
        // Interactive elements with click handlers
        const clickables = document.querySelectorAll('[onclick], [role="button"]');
        for (const clickable of clickables) {
          if (clickable.offsetParent !== null) { // Check if visible
            results.push({
              type: 'clickable',
              text: clickable.textContent,
              id: clickable.id,
              selector: clickable.tagName.toLowerCase() + (clickable.id ? `#${clickable.id}` : '')
            });
          }
        }
        
        return results;
      });
      
      // Click on elements one by one
      for (const element of clickableElements) {
        try {
          // Create a new page for each interaction to avoid state changes
          const interactionPage = await this.browser.newPage();
          
          // Set viewport
          await interactionPage.setViewport(this.options.viewport);
          
          // Set user agent
          await interactionPage.setUserAgent(this.options.userAgent);
          
          // Set timeouts
          interactionPage.setDefaultTimeout(this.options.timeout);
          interactionPage.setDefaultNavigationTimeout(this.options.timeout);
          
          // Navigate to the URL
          await interactionPage.goto(currentUrl, {
            waitUntil: 'networkidle2',
            timeout: this.options.timeout
          });
          
          // Wait for additional time if specified
          if (this.options.waitTime > 0) {
            await interactionPage.waitForTimeout(this.options.waitTime);
          }
          
          // Try to find and click the element
          let clicked = false;
          
          if (element.id) {
            try {
              await interactionPage.click(`#${element.id}`);
              clicked = true;
            } catch (error) {
              // Element not found or not clickable
            }
          }
          
     
(Content truncated due to size limit. Use line ranges to read in chunks)
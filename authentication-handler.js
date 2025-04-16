/**
 * Authentication Handler Module
 * 
 * This module provides functionality for handling authentication in web applications
 * during security testing. It supports various authentication methods and session management.
 */

const puppeteer = require('puppeteer');
const axios = require('axios');
const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class AuthenticationHandler extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      timeout: options.timeout || 30000,
      waitTime: options.waitTime || 1000,
      userAgent: options.userAgent || 'SecurScan Pro Security Scanner',
      viewport: options.viewport || { width: 1366, height: 768 },
      screenshotDirectory: options.screenshotDirectory || './screenshots',
      cookieJar: options.cookieJar || {},
      logResults: options.logResults !== false,
      logDirectory: options.logDirectory || './logs',
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
    this.page = null;
    this.authenticated = false;
    this.authMethod = null;
    this.sessionData = {
      cookies: [],
      localStorage: {},
      sessionStorage: {},
      headers: {}
    };
  }

  /**
   * Initialize the authentication handler
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
      
      this.page = await this.browser.newPage();
      
      // Set viewport
      await this.page.setViewport(this.options.viewport);
      
      // Set user agent
      await this.page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      this.page.setDefaultTimeout(this.options.timeout);
      this.page.setDefaultNavigationTimeout(this.options.timeout);
      
      this.emit('initialized');
    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Authenticate using form-based authentication
   * @param {Object} config - Authentication configuration
   * @returns {Promise<Object>} - Session data
   */
  async authenticateWithForm(config) {
    try {
      await this.initialize();
      
      const {
        loginUrl,
        usernameField,
        passwordField,
        username,
        password,
        submitButton,
        successCheck,
        otpField,
        otpValue,
        additionalFields
      } = config;
      
      // Navigate to login page
      await this.page.goto(loginUrl, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Wait for additional time if specified
      if (this.options.waitTime > 0) {
        await this.page.waitForTimeout(this.options.waitTime);
      }
      
      // Take a screenshot before login
      const beforeLoginScreenshot = path.join(
        this.options.screenshotDirectory,
        `before_login_${Date.now()}.png`
      );
      
      await this.page.screenshot({
        path: beforeLoginScreenshot,
        fullPage: true
      });
      
      // Fill username field
      await this.page.type(usernameField, username);
      
      // Fill password field
      await this.page.type(passwordField, password);
      
      // Fill additional fields if provided
      if (additionalFields) {
        for (const [selector, value] of Object.entries(additionalFields)) {
          await this.page.type(selector, value);
        }
      }
      
      // Click submit button
      await this.page.click(submitButton);
      
      // Wait for navigation
      await this.page.waitForNavigation({
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Handle OTP if needed
      if (otpField && otpValue) {
        await this.page.type(otpField, otpValue);
        
        // Click submit button again
        await this.page.click(submitButton);
        
        // Wait for navigation
        await this.page.waitForNavigation({
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
      }
      
      // Take a screenshot after login
      const afterLoginScreenshot = path.join(
        this.options.screenshotDirectory,
        `after_login_${Date.now()}.png`
      );
      
      await this.page.screenshot({
        path: afterLoginScreenshot,
        fullPage: true
      });
      
      // Check if login was successful
      let isAuthenticated = false;
      
      if (successCheck.type === 'url') {
        isAuthenticated = this.page.url().includes(successCheck.value);
      } else if (successCheck.type === 'element') {
        try {
          await this.page.waitForSelector(successCheck.value, {
            timeout: this.options.timeout / 2
          });
          isAuthenticated = true;
        } catch (error) {
          isAuthenticated = false;
        }
      } else if (successCheck.type === 'content') {
        const content = await this.page.content();
        isAuthenticated = content.includes(successCheck.value);
      }
      
      if (!isAuthenticated) {
        throw new Error('Authentication failed');
      }
      
      // Extract session data
      await this.extractSessionData();
      
      this.authenticated = true;
      this.authMethod = 'form';
      
      this.emit('authenticated', {
        method: 'form',
        url: loginUrl,
        username: username,
        sessionData: this.sessionData
      });
      
      // Log results if enabled
      if (this.options.logResults) {
        this.logAuthenticationResults('form', loginUrl, username);
      }
      
      return this.sessionData;
    } catch (error) {
      this.emit('error', {
        method: 'form',
        error: error.message
      });
      
      throw error;
    }
  }

  /**
   * Authenticate using HTTP Basic authentication
   * @param {Object} config - Authentication configuration
   * @returns {Promise<Object>} - Session data
   */
  async authenticateWithBasic(config) {
    try {
      await this.initialize();
      
      const {
        url,
        username,
        password,
        successCheck
      } = config;
      
      // Set HTTP Basic authentication credentials
      await this.page.authenticate({
        username: username,
        password: password
      });
      
      // Navigate to the URL
      await this.page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Wait for additional time if specified
      if (this.options.waitTime > 0) {
        await this.page.waitForTimeout(this.options.waitTime);
      }
      
      // Take a screenshot
      const screenshot = path.join(
        this.options.screenshotDirectory,
        `basic_auth_${Date.now()}.png`
      );
      
      await this.page.screenshot({
        path: screenshot,
        fullPage: true
      });
      
      // Check if authentication was successful
      let isAuthenticated = false;
      
      if (successCheck.type === 'url') {
        isAuthenticated = this.page.url().includes(successCheck.value);
      } else if (successCheck.type === 'element') {
        try {
          await this.page.waitForSelector(successCheck.value, {
            timeout: this.options.timeout / 2
          });
          isAuthenticated = true;
        } catch (error) {
          isAuthenticated = false;
        }
      } else if (successCheck.type === 'content') {
        const content = await this.page.content();
        isAuthenticated = content.includes(successCheck.value);
      } else if (successCheck.type === 'status') {
        const response = await axios.get(url, {
          auth: {
            username: username,
            password: password
          },
          validateStatus: () => true
        });
        
        isAuthenticated = response.status === successCheck.value;
      }
      
      if (!isAuthenticated) {
        throw new Error('Authentication failed');
      }
      
      // Extract session data
      await this.extractSessionData();
      
      // Add Basic auth header
      const authString = `${username}:${password}`;
      const base64Auth = Buffer.from(authString).toString('base64');
      this.sessionData.headers['Authorization'] = `Basic ${base64Auth}`;
      
      this.authenticated = true;
      this.authMethod = 'basic';
      
      this.emit('authenticated', {
        method: 'basic',
        url: url,
        username: username,
        sessionData: this.sessionData
      });
      
      // Log results if enabled
      if (this.options.logResults) {
        this.logAuthenticationResults('basic', url, username);
      }
      
      return this.sessionData;
    } catch (error) {
      this.emit('error', {
        method: 'basic',
        error: error.message
      });
      
      throw error;
    }
  }

  /**
   * Authenticate using JWT
   * @param {Object} config - Authentication configuration
   * @returns {Promise<Object>} - Session data
   */
  async authenticateWithJwt(config) {
    try {
      const {
        url,
        username,
        password,
        tokenEndpoint,
        clientId,
        clientSecret,
        grantType,
        scope,
        tokenLocation,
        successCheck
      } = config;
      
      // Get JWT token
      const tokenResponse = await axios.post(tokenEndpoint, {
        grant_type: grantType || 'password',
        client_id: clientId,
        client_secret: clientSecret,
        username: username,
        password: password,
        scope: scope
      }, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });
      
      if (!tokenResponse.data.access_token) {
        throw new Error('Failed to obtain JWT token');
      }
      
      const token = tokenResponse.data.access_token;
      
      // Initialize browser if needed
      await this.initialize();
      
      // Set token in appropriate location
      if (tokenLocation === 'header') {
        this.sessionData.headers['Authorization'] = `Bearer ${token}`;
      } else if (tokenLocation === 'cookie') {
        await this.page.setCookie({
          name: 'jwt',
          value: token,
          domain: new URL(url).hostname
        });
        
        this.sessionData.cookies.push({
          name: 'jwt',
          value: token,
          domain: new URL(url).hostname
        });
      }
      
      // Navigate to the URL
      await this.page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Wait for additional time if specified
      if (this.options.waitTime > 0) {
        await this.page.waitForTimeout(this.options.waitTime);
      }
      
      // Take a screenshot
      const screenshot = path.join(
        this.options.screenshotDirectory,
        `jwt_auth_${Date.now()}.png`
      );
      
      await this.page.screenshot({
        path: screenshot,
        fullPage: true
      });
      
      // Check if authentication was successful
      let isAuthenticated = false;
      
      if (successCheck.type === 'url') {
        isAuthenticated = this.page.url().includes(successCheck.value);
      } else if (successCheck.type === 'element') {
        try {
          await this.page.waitForSelector(successCheck.value, {
            timeout: this.options.timeout / 2
          });
          isAuthenticated = true;
        } catch (error) {
          isAuthenticated = false;
        }
      } else if (successCheck.type === 'content') {
        const content = await this.page.content();
        isAuthenticated = content.includes(successCheck.value);
      } else if (successCheck.type === 'status') {
        const response = await axios.get(url, {
          headers: {
            'Authorization': `Bearer ${token}`
          },
          validateStatus: () => true
        });
        
        isAuthenticated = response.status === successCheck.value;
      }
      
      if (!isAuthenticated) {
        throw new Error('Authentication failed');
      }
      
      // Extract session data
      await this.extractSessionData();
      
      this.authenticated = true;
      this.authMethod = 'jwt';
      
      this.emit('authenticated', {
        method: 'jwt',
        url: url,
        username: username,
        token: token,
        sessionData: this.sessionData
      });
      
      // Log results if enabled
      if (this.options.logResults) {
        this.logAuthenticationResults('jwt', url, username);
      }
      
      return this.sessionData;
    } catch (error) {
      this.emit('error', {
        method: 'jwt',
        error: error.message
      });
      
      throw error;
    }
  }

  /**
   * Authenticate using OAuth
   * @param {Object} config - Authentication configuration
   * @returns {Promise<Object>} - Session data
   */
  async authenticateWithOAuth(config) {
    try {
      const {
        url,
        authorizationEndpoint,
        tokenEndpoint,
        clientId,
        clientSecret,
        redirectUri,
        scope,
        username,
        password,
        usernameField,
        passwordField,
        submitButton,
        successCheck
      } = config;
      
      // Initialize browser if needed
      await this.initialize();
      
      // Navigate to authorization endpoint with client ID and redirect URI
      const authUrl = new URL(authorizationEndpoint);
      authUrl.searchParams.append('client_id', clientId);
      authUrl.searchParams.append('redirect_uri', redirectUri);
      authUrl.searchParams.append('response_type', 'code');
      authUrl.searchParams.append('scope', scope);
      
      await this.page.goto(authUrl.toString(), {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Wait for additional time if specified
      if (this.options.waitTime > 0) {
        await this.page.waitForTimeout(this.options.waitTime);
      }
      
      // Take a screenshot before login
      const beforeLoginScreenshot = path.join(
        this.options.screenshotDirectory,
        `oauth_before_login_${Date.now()}.png`
      );
      
      await this.page.screenshot({
        path: beforeLoginScreenshot,
        fullPage: true
      });
      
      // Fill username field
      await this.page.type(usernameField, username);
      
      // Fill password field
      await this.page.type(passwordField, password);
      
      // Click submit button
      await this.page.click(submitButton);
      
      // Wait for redirect to redirect URI
      await this.page.waitForNavigation({
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Take a screenshot after login
      const afterLoginScreenshot = path.join(
        this.options.screenshotDirectory,
        `oauth_after_login_${Date.now()}.png`
      );
      
      await this.page.screenshot({
        path: afterLoginScreenshot,
        fullPage: true
      });
      
      // Extract authorization code from URL
      const currentUrl = this.page.url();
      const codeMatch = currentUrl.match(/code=([^&]+)/);
      
      if (!codeMatch) {
        throw new Error('Failed to obtain authorization code');
      }
      
      const 
(Content truncated due to size limit. Use line ranges to read in chunks)
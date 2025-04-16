/**
 * Session Management Analyzer Module
 * 
 * This module provides functionality for analyzing session management in web applications
 * to identify security vulnerabilities and weaknesses.
 */

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const puppeteer = require('puppeteer');

class SessionManagementAnalyzer extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      timeout: options.timeout || 30000,
      waitTime: options.waitTime || 1000,
      userAgent: options.userAgent || 'SecurScan Pro Security Scanner',
      viewport: options.viewport || { width: 1366, height: 768 },
      screenshotDirectory: options.screenshotDirectory || './screenshots',
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
    this.findings = [];
  }

  /**
   * Initialize the session management analyzer
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
   * Analyze session management for a web application
   * @param {Object} config - Analysis configuration
   * @returns {Promise<Array>} - Analysis findings
   */
  async analyze(config) {
    try {
      await this.initialize();
      
      const {
        url,
        authHandler,
        sessionData
      } = config;
      
      this.findings = [];
      
      // Run all session management tests
      await this.testSessionIdAttributes(url, sessionData);
      await this.testSessionFixation(url, authHandler);
      await this.testSessionExpiration(url, sessionData);
      await this.testConcurrentSessions(url, authHandler);
      await this.testLogoutFunctionality(url, authHandler, sessionData);
      await this.testSessionIdleTimeout(url, sessionData);
      await this.testSessionRegeneration(url, authHandler);
      await this.testCsrfProtection(url, sessionData);
      await this.testHttpOnlyCookies(sessionData);
      await this.testSecureCookies(sessionData);
      await this.testSameSiteCookies(sessionData);
      await this.testSessionPredictability(url, authHandler);
      
      // Log results if enabled
      if (this.options.logResults) {
        this.logAnalysisResults(url);
      }
      
      this.emit('analysisCompleted', {
        url: url,
        findingsCount: this.findings.length,
        findings: this.findings
      });
      
      return this.findings;
    } catch (error) {
      this.emit('error', {
        error: `Session management analysis error: ${error.message}`
      });
      
      throw error;
    }
  }

  /**
   * Test session ID attributes
   * @param {string} url - Target URL
   * @param {Object} sessionData - Session data
   * @returns {Promise<void>}
   */
  async testSessionIdAttributes(url, sessionData) {
    try {
      // Check for session cookies
      const sessionCookies = sessionData.cookies.filter(cookie => 
        cookie.name.toLowerCase().includes('session') || 
        cookie.name.toLowerCase().includes('sid') || 
        cookie.name.toLowerCase().includes('auth') || 
        cookie.name.toLowerCase().includes('token')
      );
      
      if (sessionCookies.length === 0) {
        this.addFinding({
          type: 'session-id-missing',
          severity: 'medium',
          confidence: 'medium',
          description: 'No session cookies found',
          evidence: 'No cookies with names containing "session", "sid", "auth", or "token" were found',
          remediation: 'Implement proper session management with session cookies'
        });
        
        return;
      }
      
      // Check each session cookie
      for (const cookie of sessionCookies) {
        // Check cookie length
        if (cookie.value.length < 16) {
          this.addFinding({
            type: 'session-id-length',
            severity: 'high',
            confidence: 'high',
            description: 'Session ID is too short',
            evidence: `Cookie "${cookie.name}" has a value length of ${cookie.value.length} characters`,
            remediation: 'Use session IDs with at least 128 bits (16 bytes) of entropy'
          });
        }
        
        // Check for HttpOnly flag
        if (!cookie.httpOnly) {
          this.addFinding({
            type: 'session-id-httponly',
            severity: 'high',
            confidence: 'high',
            description: 'Session cookie missing HttpOnly flag',
            evidence: `Cookie "${cookie.name}" does not have the HttpOnly flag set`,
            remediation: 'Set the HttpOnly flag for all session cookies to prevent access from JavaScript'
          });
        }
        
        // Check for Secure flag
        if (!cookie.secure) {
          this.addFinding({
            type: 'session-id-secure',
            severity: 'high',
            confidence: 'high',
            description: 'Session cookie missing Secure flag',
            evidence: `Cookie "${cookie.name}" does not have the Secure flag set`,
            remediation: 'Set the Secure flag for all session cookies to ensure they are only sent over HTTPS'
          });
        }
        
        // Check for SameSite attribute
        if (!cookie.sameSite || cookie.sameSite === 'None') {
          this.addFinding({
            type: 'session-id-samesite',
            severity: 'medium',
            confidence: 'high',
            description: 'Session cookie missing or has weak SameSite attribute',
            evidence: `Cookie "${cookie.name}" has SameSite=${cookie.sameSite || 'not set'}`,
            remediation: 'Set the SameSite attribute to "Lax" or "Strict" for all session cookies to prevent CSRF attacks'
          });
        }
        
        // Check for path attribute
        if (cookie.path === '/' || !cookie.path) {
          this.addFinding({
            type: 'session-id-path',
            severity: 'low',
            confidence: 'medium',
            description: 'Session cookie has broad path scope',
            evidence: `Cookie "${cookie.name}" has path=${cookie.path || '/'}`,
            remediation: 'Limit the path scope of session cookies to the minimum required path'
          });
        }
        
        // Check for domain attribute
        if (cookie.domain && cookie.domain.startsWith('.')) {
          this.addFinding({
            type: 'session-id-domain',
            severity: 'low',
            confidence: 'medium',
            description: 'Session cookie has broad domain scope',
            evidence: `Cookie "${cookie.name}" has domain=${cookie.domain}`,
            remediation: 'Limit the domain scope of session cookies to the specific host rather than allowing subdomains'
          });
        }
      }
    } catch (error) {
      this.emit('error', {
        error: `Error testing session ID attributes: ${error.message}`
      });
    }
  }

  /**
   * Test for session fixation vulnerabilities
   * @param {string} url - Target URL
   * @param {Object} authHandler - Authentication handler
   * @returns {Promise<void>}
   */
  async testSessionFixation(url, authHandler) {
    try {
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Navigate to the URL
      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Get pre-authentication cookies
      const preAuthCookies = await page.cookies();
      
      // Get session cookies
      const preAuthSessionCookies = preAuthCookies.filter(cookie => 
        cookie.name.toLowerCase().includes('session') || 
        cookie.name.toLowerCase().includes('sid') || 
        cookie.name.toLowerCase().includes('auth') || 
        cookie.name.toLowerCase().includes('token')
      );
      
      // Authenticate
      await authHandler.applySessionData(page);
      
      // Navigate to the URL again
      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Get post-authentication cookies
      const postAuthCookies = await page.cookies();
      
      // Get session cookies
      const postAuthSessionCookies = postAuthCookies.filter(cookie => 
        cookie.name.toLowerCase().includes('session') || 
        cookie.name.toLowerCase().includes('sid') || 
        cookie.name.toLowerCase().includes('auth') || 
        cookie.name.toLowerCase().includes('token')
      );
      
      // Check if session cookies changed after authentication
      for (const preAuthCookie of preAuthSessionCookies) {
        const postAuthCookie = postAuthSessionCookies.find(cookie => cookie.name === preAuthCookie.name);
        
        if (postAuthCookie && postAuthCookie.value === preAuthCookie.value) {
          this.addFinding({
            type: 'session-fixation',
            severity: 'high',
            confidence: 'high',
            description: 'Session fixation vulnerability detected',
            evidence: `Cookie "${preAuthCookie.name}" value did not change after authentication`,
            remediation: 'Generate a new session ID after authentication to prevent session fixation attacks'
          });
        }
      }
      
      // Close the page
      await page.close();
    } catch (error) {
      this.emit('error', {
        error: `Error testing session fixation: ${error.message}`
      });
    }
  }

  /**
   * Test session expiration
   * @param {string} url - Target URL
   * @param {Object} sessionData - Session data
   * @returns {Promise<void>}
   */
  async testSessionExpiration(url, sessionData) {
    try {
      // Check for session cookies with expiration
      const sessionCookies = sessionData.cookies.filter(cookie => 
        cookie.name.toLowerCase().includes('session') || 
        cookie.name.toLowerCase().includes('sid') || 
        cookie.name.toLowerCase().includes('auth') || 
        cookie.name.toLowerCase().includes('token')
      );
      
      for (const cookie of sessionCookies) {
        // Check if cookie has expiration
        if (!cookie.expires) {
          this.addFinding({
            type: 'session-expiration-missing',
            severity: 'medium',
            confidence: 'high',
            description: 'Session cookie has no expiration',
            evidence: `Cookie "${cookie.name}" does not have an expiration time`,
            remediation: 'Set appropriate expiration times for session cookies'
          });
          continue;
        }
        
        // Check if expiration is too far in the future
        const expirationDate = new Date(cookie.expires * 1000);
        const now = new Date();
        const daysDifference = (expirationDate - now) / (1000 * 60 * 60 * 24);
        
        if (daysDifference > 7) {
          this.addFinding({
            type: 'session-expiration-too-long',
            severity: 'medium',
            confidence: 'high',
            description: 'Session cookie has long expiration time',
            evidence: `Cookie "${cookie.name}" expires in ${Math.round(daysDifference)} days`,
            remediation: 'Set shorter expiration times for session cookies (1 day or less is recommended)'
          });
        }
      }
    } catch (error) {
      this.emit('error', {
        error: `Error testing session expiration: ${error.message}`
      });
    }
  }

  /**
   * Test concurrent sessions
   * @param {string} url - Target URL
   * @param {Object} authHandler - Authentication handler
   * @returns {Promise<void>}
   */
  async testConcurrentSessions(url, authHandler) {
    try {
      // Create two pages
      const page1 = await this.browser.newPage();
      const page2 = await this.browser.newPage();
      
      // Set viewport
      await page1.setViewport(this.options.viewport);
      await page2.setViewport(this.options.viewport);
      
      // Set user agent
      await page1.setUserAgent(this.options.userAgent);
      await page2.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page1.setDefaultTimeout(this.options.timeout);
      page1.setDefaultNavigationTimeout(this.options.timeout);
      page2.setDefaultTimeout(this.options.timeout);
      page2.setDefaultNavigationTimeout(this.options.timeout);
      
      // Apply session data to both pages
      await authHandler.applySessionData(page1);
      await authHandler.applySessionData(page2);
      
      // Navigate to the URL on both pages
      await page1.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      await page2.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Check if both pages are authenticated
      const isPage1Authenticated = await authHandler.isSessionValid({
        url: url,
        validationMethod: 'url',
        validationValue: url
      });
      
      const isPage2Authenticated = await authHandler.isSessionValid({
        url: url,
        validationMethod: 'url',
        validationValue: url
      });
      
      if (isPage1Authenticated && isPage2Authenticated) {
        // No finding, concurrent sessions are allowed
      } else {
        this.addFinding({
          type: 'concurrent-sessions-restricted',
          severity: 'info',
          confidence: 'medium',
          description: 'Concurrent sessions are restricted',
          evidence: 'Unable to maintain multiple authenticated sessions simultaneously',
          remediation: 'This is generally a good security practice, but ensure users are properly notified when their session is terminated'
        });
      }
      
      // Close the pages
      await page1.close();
      await page2.close();
    } catch (error) {
      this.emit('error', {
        error: `Error testing concurrent sessions: ${error.message}`
      });
    }
  }

  /**
   * Test logout functionality
   * @param {string} url - Target URL
   * @param {Object} authHandler - Authentication handler
   * @param {Object} sessionData - Session data
   * @returns {Promise<void>}
   */
  async testLogoutFunctionality(url, authHandler, sessionData) {
    try {
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Apply session data
      await authHandler.applySessionData(page);
      
      // Navigate to the URL
      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Look for logout links
      const logoutLinks = await page.evaluate(() => {
        const links = Array.from(document.querySelectorAll('a'));
        return links
          .filter(link => {
            const text = link.textContent.toLowerCase();
            const href = link.href.toLowerCase();
            return text.includes('logout') || 
                   text.includes('log out') || 
                   text.includes('sign out') || 
                   href.includes('logout') || 
                   href.includes('signout');
          })
          .map(link => link.href);
      });
      
      if (logoutLinks.length === 0) {
        this.addFinding({
          type: 'logout-functionality-missing',
          severity: 'medium',
          confidence: 'medium',
          description: 'Logout functionality not found',
          evidence: 'No logout links found on the authenticated page',
          remediation: 'Implement a clear and accessible logout function on all authenticated pages'
        });
        
        await page.close();
        return;
      }
      
      // Click the first logout link
      await page.goto(logoutLinks[0], {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Check if session cookies are cleared after logout
      const postLogoutCookies = await page.cookies();
      
      // Get session cookies
      const sessionCookies = sessionData.cookies.filter(cookie => 
        cookie.name.toLowerCase().includes('session') || 
        cookie.name.toLowerCase().includes('sid') || 
        cookie.name.toLowerCase().includes('auth') || 
        cookie.name.toLowerCase().includes('token')
      );
      
      for (const sessionCookie of sessionCookies) {
        const postLogoutCookie = postLogoutCookies.find(cookie => cookie.name === sessionCookie.name);
        
        if (postLogoutCookie && postLogoutCookie.value === sessionCookie.value) {
          this.addFinding({
            type: 'logout-session-not-invalidated',
            severity: 'high',
            confidence: 'high',
            description: 'Session not invalidated after logout',
            evidence: `Cookie "${sessionCookie.name}" value did not change after logout`,
            remediation: 'Invalidate and clear all session cookies when a user logs out'
          });
        }
      }
      
      // Try to access the authenticated page again
      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Check if still authenticated
      const isStillAuthenticated = await authHandler.isSessionValid({
        url: url,
        validationMethod: 'url',
        validationValue: url
      });
      
      if (isStillAuthenticated) {
        this.addFinding({
          type: 'logout-ineffective',
          severity: 'high',
          confidence: 'high',
          description: 'Logout is ineffective',
          evidence: 'Still able to access authenticated content after logout',
          remediation: 'Ensure logout properly invalidates the session on the server side'
        });
      }
      
      // Close the page
      await page.close();
    } catch (error) {
      this.emit('error', {
        error: `Error testing logout functionality: ${error.message}`
      });
    }
  }

  /**
   * Test session idle timeout
   * @param {string} url - Target URL
   * @param {Object} sessionData - Session data
   * @returns {Promise<void>}
   */
  async testSessionIdleTimeout(url, sessionData) {
    try {
      // This test would require waiting for the idle timeout, which may be too long
      // Instead, we'll check for client-side timeout mechanisms
      
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Navigate to the URL
      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Check for client-side timeout mechanisms
      const hasTimeoutMechanism = await page.evaluate(() => {
        // Check for common timeout functions
        const pageSource = document.documentElement.outerHTML;
        return pageSource.includes('setTimeout') && 
               (pageSource.includes('idle') || 
                pageSource.includes('timeout') || 
                pageSource.includes('inactivity'));
      });
      
      if (!hasTimeoutMechanism) {
        this.addFinding({
          type: 'session-idle-timeout-missing',
          severity: 'low',
          confidence: 'low',
          description: 'No client-side session idle timeout detected',
          evidence: 'No client-side timeout mechanisms found',
          remediation: 'Implement both client-side and server-side session idle timeouts'
        });
      }
      
      // Close the page
      await page.close();
    } catch (error) {
      this.emit('error', {
        error: `Error testing session idle timeout: ${error.message}`
      });
    }
  }

  /**
   * Test session regeneration
   * @param {string} url - Target URL
   * @param {Object} authHandler - Authentication handler
   * @returns {Promise<void>}
   */
  async testSessionRegeneration(url, authHandler) {
    try {
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Apply session data
      await authHandler.applySessionData(page);
      
      // Navigate to the URL
      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Get initial cookies
      const initialCookies = await page.cookies();
      
      // Get session cookies
      const initialSessionCookies = initialCookies.filter(cookie => 
        cookie.name.toLowerCase().includes('session') || 
        cookie.name.toLowerCase().includes('sid') || 
        cookie.name.toLowerCase().includes('auth') || 
        cookie.name.toLowerCase().includes('token')
      );
      
      // Perform actions that might trigger session regeneration
      // For example, change password or email
      
      // Look for account settings links
      const accountLinks = await page.evaluate(() => {
        const links = Array.from(document.querySelectorAll('a'));
        return links
          .filter(link => {
            const text = link.textContent.toLowerCase();
            const href = link.href.toLowerCase();
            return text.includes('account') || 
                   text.includes('profile') || 
                   text.includes('settings') || 
                   href.includes('account') || 
                   href.includes('profile') || 
                   href.includes('settings');
          })
          .map(link => link.href);
      });
      
      if (accountLinks.length > 0) {
        // Navigate to account settings
        await page.goto(accountLinks[0], {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
        
        // Look for password change form
        const hasPasswordForm = await page.evaluate(() => {
          const forms = Array.from(document.querySelectorAll('form'));
          return forms.some(form => {
            const formHtml = form.outerHTML.toLowerCase();
            return formHtml.includes('password');
          });
        });
        
        if (hasPasswordForm) {
          // Submit password change form (this is a simplified example)
          await page.evaluate(() => {
            const forms = Array.from(document.querySelectorAll('form'));
            const passwordForm = forms.find(form => {
              const formHtml = form.outerHTML.toLowerCase();
              return formHtml.includes('password');
            });
            
            if (passwordForm) {
              const passwordFields = passwordForm.querySelectorAll('input[type="password"]');
              
              for (const field of passwordFields) {
                field.value = 'NewPassword123!';
              }
              
              passwordForm.submit();
            }
          });
          
          // Wait for navigation
          await page.waitForNavigation({
            waitUntil: 'networkidle2',
            timeout: this.options.timeout
          }).catch(() => {
            // Navigation might not happen, that's okay
          });
          
          // Get cookies after password change
          const afterChangeCookies = await page.cookies();
          
          // Get session cookies
          const afterChangeSessionCookies = afterChangeCookies.filter(cookie => 
            cookie.name.toLowerCase().includes('session') || 
            cookie.name.toLowerCase().includes('sid') || 
            cookie.name.toLowerCase().includes('auth') || 
            cookie.name.toLowerCase().includes('token')
          );
          
          // Check if session cookies changed
          let sessionRegenerated = false;
          
          for (const initialCookie of initialSessionCookies) {
            const afterChangeCookie = afterChangeSessionCookies.find(cookie => cookie.name === initialCookie.name);
            
            if (afterChangeCookie && afterChangeCookie.value !== initialCookie.value) {
              sessionRegenerated = true;
              break;
            }
          }
          
          if (!sessionRegenerated) {
            this.addFinding({
              type: 'session-regeneration-missing',
              severity: 'medium',
              confidence: 'medium',
              description: 'Session not regenerated after sensitive action',
              evidence: 'Session cookies did not change after password change',
              remediation: 'Regenerate session IDs after sensitive actions like password changes'
            });
          }
        }
      }
      
      // Close the page
      await page.close();
    } catch (error) {
      this.emit('error', {
        error: `Error testing session regeneration: ${error.message}`
      });
    }
  }

  /**
   * Test CSRF protection
   * @param {string} url - Target URL
   * @param {Object} sessionData - Session data
   * @returns {Promise<void>}
   */
  async testCsrfProtection(url, sessionData) {
    try {
      // Create a new page
      const page = await this.browser.newPage();
      
      // Set viewport
      await page.setViewport(this.options.viewport);
      
      // Set user agent
      await page.setUserAgent(this.options.userAgent);
      
      // Set timeouts
      page.setDefaultTimeout(this.options.timeout);
      page.setDefaultNavigationTimeout(this.options.timeout);
      
      // Navigate to the URL
      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.options.timeout
      });
      
      // Check for CSRF tokens in forms
      const csrfTokens = await page.evaluate(() => {
        const forms = Array.from(document.querySelectorAll('form'));
        const tokens = [];
        
        for (const form of forms) {
          // Check for hidden input fields that might contain CSRF tokens
          const hiddenInputs = form.querySelectorAll('input[type="hidden"]');
          
          for (const input of hiddenInputs) {
            const name = input.name.toLowerCase();
            const value = input.value;
            
            if (name.includes('csrf') || 
                name.includes('token') || 
                name.includes('nonce') || 
                name === '_token' || 
                name === 'authenticity_token') {
              tokens.push({
                form: form.action,
                tokenName: input.name,
                tokenValue: value
              });
            }
          }
        }
        
        return tokens;
      });
      
      // Check for CSRF tokens in headers
      const headers = await page.evaluate(() => {
        const metaTags = Array.from(document.querySelectorAll('meta'));
        const csrfHeaders = [];
        
        for (const meta of metaTags) {
          const name = meta.getAttribute('name');
          const content = meta.getAttribute('content');
          
          if (name && content && 
              (name.toLowerCase().includes('csrf') || 
               name.toLowerCase().includes('token'))) {
            csrfHeaders.push({
              name: name,
              value: content
            });
          }
        }
        
        return csrfHeaders;
      });
      
      if (csrfTokens.length === 0 && headers.length === 0) {
        this.addFinding({
          type: 'csrf-protection-missing',
          severity: 'high',
          confidence: 'medium',
          description: 'CSRF protection not detected',
          evidence: 'No CSRF tokens found in forms or headers',
          remediation: 'Implement CSRF protection using tokens for all state-changing operations'
        });
      }
      
      // Close the page
      await page.close();
    } catch (error) {
      this.emit('error', {
        error: `Error testing CSRF protection: ${error.message}`
      });
    }
  }

  /**
   * Test HttpOnly cookies
   * @param {Object} sessionData - Session data
   * @returns {Promise<void>}
   */
  async testHttpOnlyCookies(sessionData) {
    try {
      // Check for session cookies without HttpOnly flag
      const sessionCookies = sessionData.cookies.filter(cookie => 
        cookie.name.toLowerCase().includes('session') || 
        cookie.name.toLowerCase().includes('sid') || 
        cookie.name.toLowerCase().includes('auth') || 
        cookie.name.toLowerCase().includes('token')
      );
      
      for (const cookie of sessionCookies) {
        if (!cookie.httpOnly) {
          this.addFinding({
            type: 'httponly-flag-missing',
            severity: 'high',
            confidence: 'high',
            description: 'HttpOnly flag missing on session cookie',
            evidence: `Cookie "${cookie.name}" does not have the HttpOnly flag set`,
            remediation: 'Set the HttpOnly flag for all session cookies to prevent access from JavaScript'
          });
        }
      }
    } catch (error) {
      this.emit('error', {
        error: `Error testing HttpOnly cookies: ${error.message}`
      });
    }
  }

  /**
   * Test Secure cookies
   * @param {Object} sessionData - Session data
   * @returns {Promise<void>}
   */
  async testSecureCookies(sessionData) {
    try {
      // Check for session cookies without Secure flag
      const sessionCookies = sessionData.cookies.filter(cookie => 
        cookie.name.toLowerCase().includes('session') || 
        cookie.name.toLowerCase().includes('sid') || 
        cookie.name.toLowerCase().includes('auth') || 
        cookie.name.toLowerCase().includes('token')
      );
      
      for (const cookie of sessionCookies) {
        if (!cookie.secure) {
          this.addFinding({
            type: 'secure-flag-missing',
            severity: 'high',
            confidence: 'high',
            description: 'Secure flag missing on session cookie',
            evidence: `Cookie "${cookie.name}" does not have the Secure flag set`,
            remediation: 'Set the Secure flag for all session cookies to ensure they are only sent over HTTPS'
          });
        }
      }
    } catch (error) {
      this.emit('error', {
        error: `Error testing Secure cookies: ${error.message}`
      });
    }
  }

  /**
   * Test SameSite cookies
   * @param {Object} sessionData - Session data
   * @returns {Promise<void>}
   */
  async testSameSiteCookies(sessionData) {
    try {
      // Check for session cookies without SameSite attribute
      const sessionCookies = sessionData.cookies.filter(cookie => 
        cookie.name.toLowerCase().includes('session') || 
        cookie.name.toLowerCase().includes('sid') || 
        cookie.name.toLowerCase().includes('auth') || 
        cookie.name.toLowerCase().includes('token')
      );
      
      for (const cookie of sessionCookies) {
        if (!cookie.sameSite || cookie.sameSite === 'None') {
          this.addFinding({
            type: 'samesite-attribute-missing',
            severity: 'medium',
            confidence: 'high',
            description: 'SameSite attribute missing or set to None on session cookie',
            evidence: `Cookie "${cookie.name}" has SameSite=${cookie.sameSite || 'not set'}`,
            remediation: 'Set the SameSite attribute to "Lax" or "Strict" for all session cookies to prevent CSRF attacks'
          });
        }
      }
    } catch (error) {
      this.emit('error', {
        error: `Error testing SameSite cookies: ${error.message}`
      });
    }
  }

  /**
   * Test session predictability
   * @param {string} url - Target URL
   * @param {Object} authHandler - Authentication handler
   * @returns {Promise<void>}
   */
  async testSessionPredictability(url, authHandler) {
    try {
      // Create multiple sessions and analyze their IDs for patterns
      const sessions = [];
      
      for (let i = 0; i < 5; i++) {
        // Create a new page
        const page = await this.browser.newPage();
        
        // Set viewport
        await page.setViewport(this.options.viewport);
        
        // Set user agent
        await page.setUserAgent(this.options.userAgent);
        
        // Set timeouts
        page.setDefaultTimeout(this.options.timeout);
        page.setDefaultNavigationTimeout(this.options.timeout);
        
        // Navigate to the URL
        await page.goto(url, {
          waitUntil: 'networkidle2',
          timeout: this.options.timeout
        });
        
        // Get cookies
        const cookies = await page.cookies();
        
        // Get session cookies
        const sessionCookies = cookies.filter(cookie => 
          cookie.name.toLowerCase().includes('session') || 
          cookie.name.toLowerCase().includes('sid') || 
          cookie.name.toLowerCase().includes('auth') || 
          cookie.name.toLowerCase().includes('token')
        );
        
        for (const cookie of sessionCookies) {
          sessions.push({
            name: cookie.name,
            value: cookie.value
          });
        }
        
        // Close the page
        await page.close();
      }
      
      // Analyze session IDs for patterns
      for (const sessionName of new Set(sessions.map(s => s.name))) {
        const sessionValues = sessions
          .filter(s => s.name === sessionName)
          .map(s => s.value);
        
        if (sessionValues.length < 2) {
          continue;
        }
        
        // Check for sequential values
        let isSequential = true;
        
        for (let i = 1; i < sessionValues.length; i++) {
          // Try to extract numeric parts
          const numericPart1 = sessionValues[i-1].replace(/[^0-9]/g, '');
          const numericPart2 = sessionValues[i].replace(/[^0-9]/g, '');
          
          if (numericPart1 && numericPart2 && 
              numericPart1.length === numericPart2.length) {
            const num1 = parseInt(numericPart1, 10);
            const num2 = parseInt(numericPart2, 10);
            
            if (isNaN(num1) || isNaN(num2) || Math.abs(num2 - num1) > 100) {
              isSequential = false;
              break;
            }
          } else {
            isSequential = false;
            break;
          }
        }
        
        if (isSequential) {
          this.addFinding({
            type: 'session-id-predictable',
            severity: 'high',
            confidence: 'medium',
            description: 'Session IDs appear to be predictable',
            evidence: `Cookie "${sessionName}" values show sequential patterns`,
            remediation: 'Use cryptographically secure random number generators for session IDs'
          });
          continue;
        }
        
        // Check for low entropy
        let totalEntropy = 0;
        
        for (const value of sessionValues) {
          const entropy = this.calculateEntropy(value);
          totalEntropy += entropy;
        }
        
        const averageEntropy = totalEntropy / sessionValues.length;
        
        if (averageEntropy < 3) {
          this.addFinding({
            type: 'session-id-low-entropy',
            severity: 'high',
            confidence: 'medium',
            description: 'Session IDs have low entropy',
            evidence: `Cookie "${sessionName}" values have an average entropy of ${averageEntropy.toFixed(2)} bits per character`,
            remediation: 'Use cryptographically secure random number generators for session IDs'
          });
        }
      }
    } catch (error) {
      this.emit('error', {
        error: `Error testing session predictability: ${error.message}`
      });
    }
  }

  /**
   * Calculate entropy of a string
   * @param {string} str - String to calculate entropy for
   * @returns {number} - Entropy in bits per character
   */
  calculateEntropy(str) {
    const len = str.length;
    const frequencies = {};
    
    for (let i = 0; i < len; i++) {
      const char = str.charAt(i);
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    
    let entropy = 0;
    
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }
    
    return entropy;
  }

  /**
   * Add a finding to the list
   * @param {Object} finding - Finding object
   */
  addFinding(finding) {
    finding.id = crypto.randomBytes(8).toString('hex');
    finding.timestamp = Date.now();
    
    this.findings.push(finding);
    
    this.emit('findingDetected', finding);
  }

  /**
   * Log analysis results to file
   * @param {string} url - Target URL
   */
  logAnalysisResults(url) {
    try {
      const logFile = path.join(
        this.options.logDirectory,
        `session_analysis_${Date.now()}.json`
      );
      
      const logData = {
        url: url,
        timestamp: Date.now(),
        findingsCount: this.findings.length,
        findings: this.findings
      };
      
      fs.writeFileSync(logFile, JSON.stringify(logData, null, 2));
    } catch (error) {
      console.error('Error logging analysis results:', error);
    }
  }

  /**
   * Get analysis findings
   * @returns {Array} - Array of findings
   */
  getFindings() {
    return this.findings;
  }

  /**
   * Clear analysis findings
   */
  clearFindings() {
    this.findings = [];
  }

  /**
   * Close the session management analyzer
   * @returns {Promise<void>}
   */
  async close() {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      
      this.emit('closed');
    }
  }
}

module.exports = SessionManagementAnalyzer;

/**
 * HTTP Request Crafter Module
 * 
 * This module provides functionality for crafting and sending custom HTTP requests.
 * It allows for detailed control over request parameters, headers, and payloads.
 */

const axios = require('axios');
const https = require('https');
const http = require('http');
const FormData = require('form-data');
const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

class HttpRequestCrafter extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      timeout: options.timeout || 30000,
      followRedirects: options.followRedirects !== false,
      maxRedirects: options.maxRedirects || 5,
      validateStatus: options.validateStatus || null,
      logRequests: options.logRequests !== false,
      logDirectory: options.logDirectory || './logs',
      defaultHeaders: options.defaultHeaders || {
        'User-Agent': 'SecurScan Pro Security Scanner',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate'
      },
      ...options
    };
    
    this.requestHistory = [];
    this.responseHistory = [];
    
    // Create log directory if it doesn't exist
    if (this.options.logRequests && !fs.existsSync(this.options.logDirectory)) {
      fs.mkdirSync(this.options.logDirectory, { recursive: true });
    }
    
    // Create axios instance with default configuration
    this.client = axios.create({
      timeout: this.options.timeout,
      maxRedirects: this.options.followRedirects ? this.options.maxRedirects : 0,
      validateStatus: this.options.validateStatus || (() => true), // Accept all status codes by default
      headers: this.options.defaultHeaders,
      decompress: true,
      httpsAgent: new https.Agent({
        rejectUnauthorized: false // Allow self-signed certificates
      })
    });
    
    // Add request interceptor for logging
    this.client.interceptors.request.use(
      (config) => {
        this.logRequest(config);
        return config;
      },
      (error) => {
        this.emit('error', error);
        return Promise.reject(error);
      }
    );
    
    // Add response interceptor for logging
    this.client.interceptors.response.use(
      (response) => {
        this.logResponse(response);
        return response;
      },
      (error) => {
        if (error.response) {
          this.logResponse(error.response);
        }
        this.emit('error', error);
        return Promise.reject(error);
      }
    );
  }

  /**
   * Send a GET request
   * @param {string} url - URL to send the request to
   * @param {Object} options - Request options
   * @returns {Promise<Object>} - Response object
   */
  async get(url, options = {}) {
    try {
      const config = this.buildRequestConfig('get', url, null, options);
      const response = await this.client.request(config);
      
      this.emit('requestCompleted', {
        method: 'GET',
        url: url,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        timestamp: Date.now()
      });
      
      return this.processResponse(response);
    } catch (error) {
      this.handleRequestError(error, 'GET', url);
      throw error;
    }
  }

  /**
   * Send a POST request
   * @param {string} url - URL to send the request to
   * @param {Object|string|FormData} data - Request body
   * @param {Object} options - Request options
   * @returns {Promise<Object>} - Response object
   */
  async post(url, data = null, options = {}) {
    try {
      const config = this.buildRequestConfig('post', url, data, options);
      const response = await this.client.request(config);
      
      this.emit('requestCompleted', {
        method: 'POST',
        url: url,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        timestamp: Date.now()
      });
      
      return this.processResponse(response);
    } catch (error) {
      this.handleRequestError(error, 'POST', url);
      throw error;
    }
  }

  /**
   * Send a PUT request
   * @param {string} url - URL to send the request to
   * @param {Object|string|FormData} data - Request body
   * @param {Object} options - Request options
   * @returns {Promise<Object>} - Response object
   */
  async put(url, data = null, options = {}) {
    try {
      const config = this.buildRequestConfig('put', url, data, options);
      const response = await this.client.request(config);
      
      this.emit('requestCompleted', {
        method: 'PUT',
        url: url,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        timestamp: Date.now()
      });
      
      return this.processResponse(response);
    } catch (error) {
      this.handleRequestError(error, 'PUT', url);
      throw error;
    }
  }

  /**
   * Send a DELETE request
   * @param {string} url - URL to send the request to
   * @param {Object} options - Request options
   * @returns {Promise<Object>} - Response object
   */
  async delete(url, options = {}) {
    try {
      const config = this.buildRequestConfig('delete', url, null, options);
      const response = await this.client.request(config);
      
      this.emit('requestCompleted', {
        method: 'DELETE',
        url: url,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        timestamp: Date.now()
      });
      
      return this.processResponse(response);
    } catch (error) {
      this.handleRequestError(error, 'DELETE', url);
      throw error;
    }
  }

  /**
   * Send a HEAD request
   * @param {string} url - URL to send the request to
   * @param {Object} options - Request options
   * @returns {Promise<Object>} - Response object
   */
  async head(url, options = {}) {
    try {
      const config = this.buildRequestConfig('head', url, null, options);
      const response = await this.client.request(config);
      
      this.emit('requestCompleted', {
        method: 'HEAD',
        url: url,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        timestamp: Date.now()
      });
      
      return this.processResponse(response);
    } catch (error) {
      this.handleRequestError(error, 'HEAD', url);
      throw error;
    }
  }

  /**
   * Send an OPTIONS request
   * @param {string} url - URL to send the request to
   * @param {Object} options - Request options
   * @returns {Promise<Object>} - Response object
   */
  async options(url, options = {}) {
    try {
      const config = this.buildRequestConfig('options', url, null, options);
      const response = await this.client.request(config);
      
      this.emit('requestCompleted', {
        method: 'OPTIONS',
        url: url,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        timestamp: Date.now()
      });
      
      return this.processResponse(response);
    } catch (error) {
      this.handleRequestError(error, 'OPTIONS', url);
      throw error;
    }
  }

  /**
   * Send a PATCH request
   * @param {string} url - URL to send the request to
   * @param {Object|string|FormData} data - Request body
   * @param {Object} options - Request options
   * @returns {Promise<Object>} - Response object
   */
  async patch(url, data = null, options = {}) {
    try {
      const config = this.buildRequestConfig('patch', url, data, options);
      const response = await this.client.request(config);
      
      this.emit('requestCompleted', {
        method: 'PATCH',
        url: url,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        timestamp: Date.now()
      });
      
      return this.processResponse(response);
    } catch (error) {
      this.handleRequestError(error, 'PATCH', url);
      throw error;
    }
  }

  /**
   * Send a custom HTTP request
   * @param {Object} config - Request configuration
   * @returns {Promise<Object>} - Response object
   */
  async request(config) {
    try {
      const response = await this.client.request(config);
      
      this.emit('requestCompleted', {
        method: config.method ? config.method.toUpperCase() : 'GET',
        url: config.url,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        timestamp: Date.now()
      });
      
      return this.processResponse(response);
    } catch (error) {
      this.handleRequestError(error, config.method ? config.method.toUpperCase() : 'GET', config.url);
      throw error;
    }
  }

  /**
   * Build a multipart form data request
   * @param {string} url - URL to send the request to
   * @param {Object} formData - Form data fields
   * @param {Object} options - Request options
   * @returns {Promise<Object>} - Response object
   */
  async sendFormData(url, formData = {}, options = {}) {
    try {
      const form = new FormData();
      
      // Add form fields
      for (const [key, value] of Object.entries(formData)) {
        if (value === null || value === undefined) {
          continue;
        }
        
        if (value.hasOwnProperty('filename') && value.hasOwnProperty('content')) {
          // File upload
          form.append(key, value.content, value.filename);
        } else if (Buffer.isBuffer(value) || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
          // Simple value
          form.append(key, value.toString());
        } else if (typeof value === 'object') {
          // JSON value
          form.append(key, JSON.stringify(value));
        }
      }
      
      // Set form headers
      const formHeaders = form.getHeaders();
      
      // Build request config
      const config = this.buildRequestConfig(
        options.method || 'post',
        url,
        form,
        {
          ...options,
          headers: {
            ...options.headers,
            ...formHeaders
          }
        }
      );
      
      const response = await this.client.request(config);
      
      this.emit('requestCompleted', {
        method: config.method.toUpperCase(),
        url: url,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        timestamp: Date.now()
      });
      
      return this.processResponse(response);
    } catch (error) {
      this.handleRequestError(error, options.method || 'POST', url);
      throw error;
    }
  }

  /**
   * Upload a file
   * @param {string} url - URL to send the request to
   * @param {string} fieldName - Form field name for the file
   * @param {string|Buffer} fileContent - File content
   * @param {string} fileName - File name
   * @param {Object} options - Request options
   * @returns {Promise<Object>} - Response object
   */
  async uploadFile(url, fieldName, fileContent, fileName, options = {}) {
    try {
      const form = new FormData();
      
      // Add file to form
      form.append(fieldName, fileContent, fileName);
      
      // Add additional form fields
      if (options.formData) {
        for (const [key, value] of Object.entries(options.formData)) {
          if (value !== null && value !== undefined) {
            form.append(key, value.toString());
          }
        }
      }
      
      // Set form headers
      const formHeaders = form.getHeaders();
      
      // Build request config
      const config = this.buildRequestConfig(
        options.method || 'post',
        url,
        form,
        {
          ...options,
          headers: {
            ...options.headers,
            ...formHeaders
          }
        }
      );
      
      const response = await this.client.request(config);
      
      this.emit('requestCompleted', {
        method: config.method.toUpperCase(),
        url: url,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        timestamp: Date.now()
      });
      
      return this.processResponse(response);
    } catch (error) {
      this.handleRequestError(error, options.method || 'POST', url);
      throw error;
    }
  }

  /**
   * Send a JSON request
   * @param {string} url - URL to send the request to
   * @param {Object} data - JSON data
   * @param {Object} options - Request options
   * @returns {Promise<Object>} - Response object
   */
  async sendJson(url, data = {}, options = {}) {
    try {
      // Build request config
      const config = this.buildRequestConfig(
        options.method || 'post',
        url,
        data,
        {
          ...options,
          headers: {
            ...options.headers,
            'Content-Type': 'application/json'
          }
        }
      );
      
      const response = await this.client.request(config);
      
      this.emit('requestCompleted', {
        method: config.method.toUpperCase(),
        url: url,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        timestamp: Date.now()
      });
      
      return this.processResponse(response);
    } catch (error) {
      this.handleRequestError(error, options.method || 'POST', url);
      throw error;
    }
  }

  /**
   * Send an XML request
   * @param {string} url - URL to send the request to
   * @param {string} xmlData - XML data
   * @param {Object} options - Request options
   * @returns {Promise<Object>} - Response object
   */
  async sendXml(url, xmlData, options = {}) {
    try {
      // Build request config
      const config = this.buildRequestConfig(
        options.method || 'post',
        url,
        xmlData,
        {
          ...options,
          headers: {
            ...options.headers,
            'Content-Type': 'application/xml'
          }
        }
      );
      
      const response = await this.client.request(config);
      
      this.emit('requestCompleted', {
        method: config.method.toUpperCase(),
        url: url,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        timestamp: Date.now()
      });
      
      return this.processResponse(response);
    } catch (error) {
      this.handleRequestError(error, options.method || 'POST', url);
      throw error;
    }
  }

  /**
   * Build request configuration
   * @param {string} method - HTTP method
   * @param {string} url - URL to send the request to
   * @param {Object|string|FormData} data - Request body
   * @param {Object} options - Request options
   * @returns {Object} - Request configuration
   */
  buildRequestConfig(method, url, data, options) {
    const config = {
      method: method,
      url: url,
      headers: {
        ...this.options.defaultHeaders,
        ...options.headers
      },
      params: options.params || {},
      timeout: options.timeout || this.options.timeout,
      maxRedirects: options.followRedirects !== false ? (options.maxRedirects || this.options.maxRedirects) : 0,
      validateStatus: options.validateStatus || this.options.validateStatus,
      responseType: options.responseType || 'arraybuffer',
      decompress: options.decompress !== false,
      auth: options.auth || null,
      proxy: options.proxy || null,
      httpsAgent: options.rejectUnauthorized === false ? 
        new https.Agent({ rejectUnauthorized: false }) : 
        this.client.defaults.httpsAgent,
      httpAgent: options.httpAgent || this.client.defaults.httpAgent
    };
    
    // Add request body if provided
    if (data !== null && data !== undefined) {
      config.data = data;
    }
    
    // Add cookies if provided
    if (options.cookies) {
      const cookieString = Object.entries(options.cookies)
        .map(([key, value]) => `${key}=${value}`)
        .join('; ');
      
      config.headers['Cookie'] = cookieString;
    }
    
    return config;
  }

  /**
   * Process response
   * @param {Object} response - Axios response object
   * @returns {Object} - Processed response
   */
  processResponse(response) {
    const contentType = response.headers['content-type'] || '';
    let data = response.data;
    
    // Convert buffer to appropriate format based on content type
    if (Buffer.isBuffer(data)) {
      if (contentType.includes('json')) {
        try {
          data = JSON.parse(data.toString('utf8'));
        } catch (error) {
          // If parsing fails, keep the buffer
          console.error('JSON parsing error:', error.message);
        }
      } else if (contentType.includes('text') || 
                contentType.includes('xml') || 
                contentType.includes('html') || 
                contentType.includes('javascript') || 
                contentType.includes('css')) {
        data = data.toString('utf8');
      }
    }
    
    return {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
      data: data,
      cookies: this.parseCookies(response.headers['set-cookie']),
      request: {
        method: response.config.method.toUpperCase(),
        url: response.config.url,
        headers: response.config.headers
      },
      timing: {
        startTime: response.config.startTime,
        endTime: Date.now(),
        duration: Date.now() - response.config.startTime
      }
    };
  }

  /**
   * Handle request error
   * @param {Error} error - Error object
   * @param {string} method - HTTP method
   * @param {string} url - Request URL
   */
  handleRequestError(error, method, url) {
    const errorInfo = {
      method: method,
      url: url,
      message: error.message,
      code: error.code,
      timestamp: Date.now()
    };
    
    if (error.response) {
      errorInfo.status = error.response.status;
      errorInfo.statusText = error.response.statusText;
      errorInfo.headers = error.response.headers;
    }
    
    this.emit('requestError', errorInfo);
  }

  /**
   * Parse cookies from Set-Cookie headers
   * @param {Array|string} setCookieHeaders - Set-Cookie headers
   * @returns {Object} - Parsed cookies
   */
  parseCookies(setCookieHeaders) {
    if (!setCookieHeaders) {
      return {};
    }
    
    const cookies = {};
    const cookieHeaders = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    
    for (const header of cookieHeaders) {
      const parts = header.split(';');
      const cookiePart = parts[0];
      const [name, value] = cookiePart.split('=');
      
      if (name && value) {
        cookies[name.trim()] = value.trim();
      }
    }
    
    return cookies;
  }

  /**
   * Log request
   * @param {Object} config - Request configuration
   */
  logRequest(config) {
    // Add start time to config for timing
    config.startTime = Date.now();
    
    // Create request info object
    const requestInfo = {
      method: config.method.toUpperCase(),
      url: config.url,
      headers: config.headers,
      params: config.params,
      data: config.data,
      timestamp: config.startTime
    };
    
    // Add to request history
    this.requestHistory.push(requestInfo);
    
    // Emit event
    this.emit('request', requestInfo);
    
    // Log to file if enabled
    if (this.options.logRequests) {
      try {
        const logFile = path.join(
          this.options.logDirectory,
          `request_${Date.now()}.json`
        );
        
        // Clone request info to avoid circular references
        const logData = { ...requestInfo };
        
        // Handle FormData
        if (config.data instanceof FormData) {
          logData.data = '[FormData]';
        }
        
        fs.writeFileSync(logFile, JSON.stringify(logData, null, 2));
      } catch (error) {
        console.error('Request logging error:', error);
      }
    }
  }

  /**
   * Log response
   * @param {Object} response - Response object
   */
  logResponse(response) {
    // Calculate request duration
    const endTime = Date.now();
    const duration = endTime - (response.config.startTime || endTime);
    
    // Create response info object
    const responseInfo = {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
      size: response.data ? (Buffer.isBuffer(response.data) ? response.data.length : JSON.stringify(response.data).length) : 0,
      timing: {
        startTime: response.config.startTime,
        endTime: endTime,
        duration: duration
      },
      request: {
        method: response.config.method.toUpperCase(),
        url: response.config.url,
        headers: response.config.headers
      },
      timestamp: endTime
    };
    
    // Add to response history
    this.responseHistory.push(responseInfo);
    
    // Emit event
    this.emit('response', responseInfo);
    
    // Log to file if enabled
    if (this.options.logRequests) {
      try {
        const logFile = path.join(
          this.options.logDirectory,
          `response_${Date.now()}.json`
        );
        
        fs.writeFileSync(logFile, JSON.stringify(responseInfo, null, 2));
        
        // Save response body to separate file if it's not too large
        if (response.data) {
          const bodyFile = path.join(
            this.options.logDirectory,
            `response_body_${Date.now()}`
          );
          
          if (Buffer.isBuffer(response.data)) {
            const contentType = response.headers['content-type'] || '';
            
            if (contentType.includes('text') || 
                contentType.includes('json') || 
                contentType.includes('xml') || 
                contentType.includes('html') || 
                contentType.includes('javascript') || 
                contentType.includes('css')) {
              fs.writeFileSync(bodyFile + '.txt', response.data.toString('utf8'));
            } else {
              fs.writeFileSync(bodyFile + '.bin', response.data);
            }
          } else if (typeof response.data === 'string') {
            fs.writeFileSync(bodyFile + '.txt', response.data);
          } else {
            fs.writeFileSync(bodyFile + '.json', JSON.stringify(response.data, null, 2));
          }
        }
      } catch (error) {
        console.error('Response logging error:', error);
      }
    }
  }

  /**
   * Get request history
   * @param {Object} options - Options for filtering history
   * @returns {Array} - Array of request history items
   */
  getRequestHistory(options = {}) {
    let history = [...this.requestHistory];
    
    // Filter by URL
    if (options.url) {
      history = history.filter(item => item.url.includes(options.url));
    }
    
    // Filter by method
    if (options.method) {
      history = history.filter(item => item.method === options.method.toUpperCase());
    }
    
    // Filter by time range
    if (options.startTime) {
      history = history.filter(item => item.timestamp >= options.startTime);
    }
    
    if (options.endTime) {
      history = history.filter(item => item.timestamp <= options.endTime);
    }
    
    // Limit number of items
    if (options.limit) {
      history = history.slice(0, options.limit);
    }
    
    return history;
  }

  /**
   * Get response history
   * @param {Object} options - Options for filtering history
   * @returns {Array} - Array of response history items
   */
  getResponseHistory(options = {}) {
    let history = [...this.responseHistory];
    
    // Filter by URL
    if (options.url) {
      history = history.filter(item => item.request.url.includes(options.url));
    }
    
    // Filter by method
    if (options.method) {
      history = history.filter(item => item.request.method === options.method.toUpperCase());
    }
    
    // Filter by status
    if (options.status) {
      history = history.filter(item => item.status === options.status);
    }
    
    // Filter by time range
    if (options.startTime) {
      history = history.filter(item => item.timestamp >= options.startTime);
    }
    
    if (options.endTime) {
      history = history.filter(item => item.timestamp <= options.endTime);
    }
    
    // Limit number of items
    if (options.limit) {
      history = history.slice(0, options.limit);
    }
    
    return history;
  }

  /**
   * Clear request and response history
   */
  clearHistory() {
    this.requestHistory = [];
    this.responseHistory = [];
  }
}

module.exports = HttpRequestCrafter;

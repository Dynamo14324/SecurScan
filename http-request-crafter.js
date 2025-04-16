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
      const cookieString = Object.entrie
(Content truncated due to size limit. Use line ranges to read in chunks)
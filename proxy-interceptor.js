/**
 * Proxy Interception Module
 * 
 * This module provides functionality for intercepting and analyzing HTTP requests and responses.
 * It allows for request modification, response analysis, and traffic monitoring.
 */

const http = require('http');
const https = require('https');
const net = require('net');
const url = require('url');
const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');
const { createProxyServer } = require('http-proxy');
const zlib = require('zlib');

class ProxyInterceptor extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      port: options.port || 8080,
      host: options.host || '0.0.0.0',
      ssl: options.ssl || false,
      sslCert: options.sslCert || null,
      sslKey: options.sslKey || null,
      interceptRequest: options.interceptRequest !== false,
      interceptResponse: options.interceptResponse !== false,
      logTraffic: options.logTraffic !== false,
      logDirectory: options.logDirectory || './logs',
      requestModifiers: options.requestModifiers || [],
      responseModifiers: options.responseModifiers || [],
      ...options
    };
    
    this.server = null;
    this.proxy = null;
    this.isRunning = false;
    this.trafficLog = [];
    this.requestLog = [];
    this.responseLog = [];
  }

  /**
   * Initialize and start the proxy server
   */
  async start() {
    if (this.isRunning) {
      return;
    }
    
    try {
      // Create log directory if it doesn't exist
      if (this.options.logTraffic && !fs.existsSync(this.options.logDirectory)) {
        fs.mkdirSync(this.options.logDirectory, { recursive: true });
      }
      
      // Create proxy server
      this.proxy = createProxyServer({
        secure: false, // Don't verify SSL certificates
        changeOrigin: true,
        autoRewrite: true,
        followRedirects: true
      });
      
      // Handle proxy errors
      this.proxy.on('error', (err, req, res) => {
        console.error('Proxy error:', err);
        this.emit('error', err);
        
        if (res && !res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Proxy error: ' + err.message);
        }
      });
      
      // Intercept requests
      if (this.options.interceptRequest) {
        this.proxy.on('proxyReq', (proxyReq, req, res, options) => {
          this.handleRequest(proxyReq, req, res, options);
        });
      }
      
      // Intercept responses
      if (this.options.interceptResponse) {
        this.proxy.on('proxyRes', (proxyRes, req, res) => {
          this.handleResponse(proxyRes, req, res);
        });
      }
      
      // Create HTTP server
      this.server = http.createServer((req, res) => {
        // Handle CONNECT method for HTTPS
        if (req.method === 'CONNECT') {
          this.handleConnect(req, res);
          return;
        }
        
        // Log request
        this.logRequest(req);
        
        // Apply request modifiers
        this.applyRequestModifiers(req);
        
        // Get target URL
        const targetUrl = req.url;
        
        // Proxy the request
        this.proxy.web(req, res, { target: targetUrl });
      });
      
      // Handle CONNECT method for HTTPS
      this.server.on('connect', (req, socket, head) => {
        this.handleConnect(req, socket, head);
      });
      
      // Start the server
      await new Promise((resolve, reject) => {
        this.server.listen(this.options.port, this.options.host, (err) => {
          if (err) {
            reject(err);
            return;
          }
          
          this.isRunning = true;
          this.emit('started', {
            host: this.options.host,
            port: this.options.port
          });
          
          resolve();
        });
      });
      
      return {
        host: this.options.host,
        port: this.options.port
      };
    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Handle HTTP CONNECT method for HTTPS connections
   * @param {Object} req - HTTP request object
   * @param {Object} socket - TCP socket
   * @param {Buffer} head - First packet of the tunneling stream
   */
  handleConnect(req, socket, head) {
    try {
      // Parse the target host and port
      const [targetHost, targetPort] = req.url.split(':');
      
      // Log the CONNECT request
      this.logConnect(req);
      
      // Create a TCP connection to the target server
      const targetSocket = net.connect(
        parseInt(targetPort) || 443,
        targetHost,
        () => {
          // Tell the client the connection is established
          socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          
          // If we have head data, write it to the target socket
          if (head && head.length > 0) {
            targetSocket.write(head);
          }
          
          // Pipe the sockets together
          socket.pipe(targetSocket);
          targetSocket.pipe(socket);
        }
      );
      
      // Handle errors
      targetSocket.on('error', (err) => {
        console.error('Target socket error:', err);
        socket.end();
      });
      
      socket.on('error', (err) => {
        console.error('Client socket error:', err);
        targetSocket.end();
      });
    } catch (error) {
      console.error('CONNECT error:', error);
      socket.end();
    }
  }

  /**
   * Handle and modify HTTP requests
   * @param {Object} proxyReq - Proxy request object
   * @param {Object} req - Original request object
   * @param {Object} res - Response object
   * @param {Object} options - Proxy options
   */
  handleRequest(proxyReq, req, res, options) {
    try {
      // Apply request modifiers
      for (const modifier of this.options.requestModifiers) {
        modifier(proxyReq, req, res, options);
      }
      
      // Log modified request
      this.logModifiedRequest(proxyReq, req);
      
      this.emit('requestIntercepted', {
        originalUrl: req.url,
        method: req.method,
        headers: req.headers,
        timestamp: Date.now()
      });
    } catch (error) {
      console.error('Request handling error:', error);
      this.emit('error', error);
    }
  }

  /**
   * Handle and modify HTTP responses
   * @param {Object} proxyRes - Proxy response object
   * @param {Object} req - Original request object
   * @param {Object} res - Response object
   */
  handleResponse(proxyRes, req, res) {
    try {
      // Get original response body
      let responseBody = Buffer.from([]);
      
      proxyRes.on('data', (chunk) => {
        responseBody = Buffer.concat([responseBody, chunk]);
      });
      
      proxyRes.on('end', () => {
        try {
          // Decompress response if needed
          let decompressedBody = responseBody;
          const contentEncoding = proxyRes.headers['content-encoding'];
          
          if (contentEncoding) {
            if (contentEncoding.includes('gzip')) {
              decompressedBody = zlib.gunzipSync(responseBody);
            } else if (contentEncoding.includes('deflate')) {
              decompressedBody = zlib.inflateSync(responseBody);
            }
          }
          
          // Convert to string if it's a text response
          let bodyString = decompressedBody;
          const contentType = proxyRes.headers['content-type'] || '';
          
          if (contentType.includes('text') || 
              contentType.includes('json') || 
              contentType.includes('xml') || 
              contentType.includes('javascript') || 
              contentType.includes('css')) {
            bodyString = decompressedBody.toString('utf8');
          }
          
          // Apply response modifiers
          let modifiedBody = bodyString;
          
          for (const modifier of this.options.responseModifiers) {
            const result = modifier(bodyString, proxyRes, req, res);
            if (result !== undefined) {
              modifiedBody = result;
            }
          }
          
          // Log response
          this.logResponse(proxyRes, req, bodyString);
          
          this.emit('responseIntercepted', {
            url: req.url,
            method: req.method,
            status: proxyRes.statusCode,
            headers: proxyRes.headers,
            contentType: contentType,
            bodyLength: responseBody.length,
            timestamp: Date.now()
          });
        } catch (error) {
          console.error('Response handling error:', error);
          this.emit('error', error);
        }
      });
    } catch (error) {
      console.error('Response handling error:', error);
      this.emit('error', error);
    }
  }

  /**
   * Apply request modifiers to a request
   * @param {Object} req - HTTP request object
   */
  applyRequestModifiers(req) {
    try {
      // Clone headers to avoid modifying the original
      const originalHeaders = { ...req.headers };
      
      // Apply each modifier
      for (const modifier of this.options.requestModifiers) {
        modifier(req);
      }
      
      // Check if headers were modified
      const headersModified = JSON.stringify(originalHeaders) !== JSON.stringify(req.headers);
      
      if (headersModified) {
        this.emit('requestModified', {
          url: req.url,
          method: req.method,
          originalHeaders: originalHeaders,
          modifiedHeaders: req.headers,
          timestamp: Date.now()
        });
      }
    } catch (error) {
      console.error('Request modifier error:', error);
      this.emit('error', error);
    }
  }

  /**
   * Log HTTP request
   * @param {Object} req - HTTP request object
   */
  logRequest(req) {
    if (!this.options.logTraffic) {
      return;
    }
    
    try {
      const requestInfo = {
        url: req.url,
        method: req.method,
        headers: req.headers,
        timestamp: Date.now()
      };
      
      this.requestLog.push(requestInfo);
      this.trafficLog.push({
        type: 'request',
        ...requestInfo
      });
      
      // Write to log file
      if (this.options.logDirectory) {
        const logFile = path.join(
          this.options.logDirectory,
          `request_${Date.now()}.json`
        );
        
        fs.writeFileSync(logFile, JSON.stringify(requestInfo, null, 2));
      }
    } catch (error) {
      console.error('Request logging error:', error);
    }
  }

  /**
   * Log modified HTTP request
   * @param {Object} proxyReq - Proxy request object
   * @param {Object} originalReq - Original request object
   */
  logModifiedRequest(proxyReq, originalReq) {
    if (!this.options.logTraffic) {
      return;
    }
    
    try {
      const requestInfo = {
        originalUrl: originalReq.url,
        url: proxyReq.path,
        method: proxyReq.method,
        originalHeaders: originalReq.headers,
        headers: proxyReq.getHeaders(),
        timestamp: Date.now()
      };
      
      // Write to log file
      if (this.options.logDirectory) {
        const logFile = path.join(
          this.options.logDirectory,
          `modified_request_${Date.now()}.json`
        );
        
        fs.writeFileSync(logFile, JSON.stringify(requestInfo, null, 2));
      }
    } catch (error) {
      console.error('Modified request logging error:', error);
    }
  }

  /**
   * Log HTTP CONNECT request
   * @param {Object} req - HTTP request object
   */
  logConnect(req) {
    if (!this.options.logTraffic) {
      return;
    }
    
    try {
      const connectInfo = {
        url: req.url,
        method: 'CONNECT',
        headers: req.headers,
        timestamp: Date.now()
      };
      
      this.trafficLog.push({
        type: 'connect',
        ...connectInfo
      });
      
      // Write to log file
      if (this.options.logDirectory) {
        const logFile = path.join(
          this.options.logDirectory,
          `connect_${Date.now()}.json`
        );
        
        fs.writeFileSync(logFile, JSON.stringify(connectInfo, null, 2));
      }
    } catch (error) {
      console.error('CONNECT logging error:', error);
    }
  }

  /**
   * Log HTTP response
   * @param {Object} proxyRes - Proxy response object
   * @param {Object} req - Original request object
   * @param {string|Buffer} body - Response body
   */
  logResponse(proxyRes, req, body) {
    if (!this.options.logTraffic) {
      return;
    }
    
    try {
      const contentType = proxyRes.headers['content-type'] || '';
      const isTextResponse = contentType.includes('text') || 
                            contentType.includes('json') || 
                            contentType.includes('xml') || 
                            contentType.includes('javascript') || 
                            contentType.includes('css');
      
      const responseInfo = {
        url: req.url,
        method: req.method,
        status: proxyRes.statusCode,
        statusMessage: proxyRes.statusMessage,
        headers: proxyRes.headers,
        contentType: contentType,
        bodyLength: body ? body.length : 0,
        body: isTextResponse && typeof body === 'string' ? body.substring(0, 1000) : '[Binary data]',
        timestamp: Date.now()
      };
      
      this.responseLog.push(responseInfo);
      this.trafficLog.push({
        type: 'response',
        ...responseInfo
      });
      
      // Write to log file
      if (this.options.logDirectory) {
        const logFile = path.join(
          this.options.logDirectory,
          `response_${Date.now()}.json`
        );
        
        fs.writeFileSync(logFile, JSON.stringify(responseInfo, null, 2));
        
        // Save response body to separate file if it's large
        if (body && body.length > 1000) {
          const bodyFile = path.join(
            this.options.logDirectory,
            `response_body_${Date.now()}`
          );
          
          if (isTextResponse && typeof body === 'string') {
            fs.writeFileSync(bodyFile + '.txt', body);
          } else {
            fs.writeFileSync(bodyFile + '.bin', body);
          }
        }
      }
    } catch (error) {
      console.error('Response logging error:', error);
    }
  }

  /**
   * Add a request modifier
   * @param {Function} modifier - Request modifier function
   */
  addRequestModifier(modifier) {
    if (typeof modifier !== 'function') {
      throw new Error('Request modifier must be a function');
    }
    
    this.options.requestModifiers.push(modifier);
  }

  /**
   * Add a response modifier
   * @param {Function} modifier - Response modifier function
   */
  addResponseModifier(modifier) {
    if (typeof modifier !== 'function') {
      throw new Error('Response modifier must be a function');
    }
    
    this.options.responseModifiers.push(modifier);
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
    
    // Filter by time range
    if (options.startTime) {
      logs = logs.filter(log => log.timestamp >= options.startTime);
    }
    
    if (options.endTime) {
      logs = logs.filter(log => log.timestamp <= options.endTime);
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
    if 
(Content truncated due to size limit. Use line ranges to read in chunks)
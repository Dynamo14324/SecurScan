const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');

// Import scanner modules
const Scanner = require('../core/scanner');
const scanner = new Scanner();

// Mock scan database for demo purposes
let scans = [
  {
    id: 'scan-123',
    target: 'https://example.com',
    targetName: 'Example Website',
    date: '2025-04-15',
    status: 'Completed',
    progress: 100,
    duration: '00:45:12',
    userId: '1',
    scanType: 'comprehensive',
    vulnerabilityTypes: ['sql-injection', 'xss', 'csrf', 'ssrf', 'xxe'],
    summary: {
      'Critical': 3,
      'High': 5,
      'Medium': 8,
      'Low': 4,
      'Info': 2
    }
  },
  {
    id: 'scan-124',
    target: 'https://test-app.com',
    targetName: 'Test Application',
    date: '2025-04-14',
    status: 'Completed',
    progress: 100,
    duration: '00:32:45',
    userId: '1',
    scanType: 'quick',
    vulnerabilityTypes: ['sql-injection', 'xss'],
    summary: {
      'Critical': 0,
      'High': 2,
      'Medium': 6,
      'Low': 8,
      'Info': 5
    }
  },
  {
    id: 'scan-125',
    target: 'https://dev.internal.org',
    targetName: 'Development Server',
    date: '2025-04-14',
    status: 'In Progress',
    progress: 65,
    duration: '00:28:10',
    userId: '2',
    scanType: 'comprehensive',
    vulnerabilityTypes: ['sql-injection', 'xss', 'csrf', 'ssrf', 'xxe'],
    summary: {
      'Critical': 1,
      'High': 3,
      'Medium': 2,
      'Low': 0,
      'Info': 1
    }
  }
];

// Middleware to check if user is authenticated
const auth = (req, res, next) => {
  // In a real app, this would verify the JWT token
  // For demo purposes, we'll just pass through
  next();
};

// Get all scans for the authenticated user
router.get('/', auth, (req, res) => {
  try {
    // In a real app, this would filter by userId from the JWT token
    // const userScans = scans.filter(scan => scan.userId === req.user.id);
    
    // For demo purposes, return all scans
    res.json(scans);
  } catch (error) {
    req.logger.error('Get scans error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get a specific scan by ID
router.get('/:id', auth, (req, res) => {
  try {
    const scan = scans.find(s => s.id === req.params.id);
    
    if (!scan) {
      return res.status(404).json({ message: 'Scan not found' });
    }
    
    // In a real app, check if the scan belongs to the user
    // if (scan.userId !== req.user.id) {
    //   return res.status(403).json({ message: 'Not authorized' });
    // }
    
    res.json(scan);
  } catch (error) {
    req.logger.error('Get scan error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start a new scan
router.post('/', auth, async (req, res) => {
  try {
    const {
      targetUrl,
      targetName,
      targetDescription,
      scanScope,
      scanType,
      vulnerabilityTypes,
      scanDepth,
      crawlOptions,
      authType,
      username,
      password,
      loginUrl,
      requestsPerSecond,
      timeout,
      followRedirects,
      userAgent,
      headers,
      cookies,
      proxySettings
    } = req.body;
    
    // Validate required fields
    if (!targetUrl || !targetName || !scanType || !vulnerabilityTypes) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Create new scan
    const newScan = {
      id: `scan-${uuidv4()}`,
      target: targetUrl,
      targetName,
      targetDescription,
      date: new Date().toISOString().split('T')[0],
      status: 'In Progress',
      progress: 0,
      duration: '00:00:00',
      userId: '1', // In a real app, this would be req.user.id
      scanType,
      vulnerabilityTypes,
      scanDepth: scanDepth || 3,
      crawlOptions: crawlOptions || { followLinks: true, maxPages: 100 },
      authConfig: {
        type: authType || 'none',
        username,
        password,
        loginUrl
      },
      requestConfig: {
        requestsPerSecond: requestsPerSecond || 10,
        timeout: timeout || 30,
        followRedirects: followRedirects !== undefined ? followRedirects : true,
        userAgent: userAgent || 'SecurScan Security Testing Platform',
        headers: headers || [],
        cookies: cookies || [],
        proxySettings: proxySettings || { useProxy: false }
      },
      summary: {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0,
        'Info': 0
      }
    };
    
    // In a real app, this would start the actual scan
    // For demo purposes, we'll just add it to our mock database
    scans.push(newScan);
    
    // Start the scan in the background
    setTimeout(() => {
      // Simulate scan progress
      let progress = 0;
      const interval = setInterval(() => {
        progress += 5;
        
        // Update scan progress
        const scanIndex = scans.findIndex(s => s.id === newScan.id);
        if (scanIndex !== -1) {
          scans[scanIndex].progress = progress;
          
          if (progress >= 100) {
            clearInterval(interval);
            
            // Update scan status and results
            scans[scanIndex].status = 'Completed';
            scans[scanIndex].duration = '00:32:15';
            scans[scanIndex].summary = {
              'Critical': Math.floor(Math.random() * 3),
              'High': Math.floor(Math.random() * 5),
              'Medium': Math.floor(Math.random() * 8),
              'Low': Math.floor(Math.random() * 6),
              'Info': Math.floor(Math.random() * 10)
            };
          }
        }
      }, 2000);
    }, 1000);
    
    res.status(201).json(newScan);
  } catch (error) {
    req.logger.error('Start scan error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete a scan
router.delete('/:id', auth, (req, res) => {
  try {
    const scanIndex = scans.findIndex(s => s.id === req.params.id);
    
    if (scanIndex === -1) {
      return res.status(404).json({ message: 'Scan not found' });
    }
    
    // In a real app, check if the scan belongs to the user
    // if (scans[scanIndex].userId !== req.user.id) {
    //   return res.status(403).json({ message: 'Not authorized' });
    // }
    
    // Remove the scan
    scans.splice(scanIndex, 1);
    
    res.json({ message: 'Scan deleted' });
  } catch (error) {
    req.logger.error('Delete scan error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Pause a scan
router.put('/:id/pause', auth, (req, res) => {
  try {
    const scanIndex = scans.findIndex(s => s.id === req.params.id);
    
    if (scanIndex === -1) {
      return res.status(404).json({ message: 'Scan not found' });
    }
    
    // In a real app, check if the scan belongs to the user
    // if (scans[scanIndex].userId !== req.user.id) {
    //   return res.status(403).json({ message: 'Not authorized' });
    // }
    
    // Check if scan is in progress
    if (scans[scanIndex].status !== 'In Progress') {
      return res.status(400).json({ message: 'Scan is not in progress' });
    }
    
    // Update scan status
    scans[scanIndex].status = 'Paused';
    
    res.json(scans[scanIndex]);
  } catch (error) {
    req.logger.error('Pause scan error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Resume a scan
router.put('/:id/resume', auth, (req, res) => {
  try {
    const scanIndex = scans.findIndex(s => s.id === req.params.id);
    
    if (scanIndex === -1) {
      return res.status(404).json({ message: 'Scan not found' });
    }
    
    // In a real app, check if the scan belongs to the user
    // if (scans[scanIndex].userId !== req.user.id) {
    //   return res.status(403).json({ message: 'Not authorized' });
    // }
    
    // Check if scan is paused
    if (scans[scanIndex].status !== 'Paused') {
      return res.status(400).json({ message: 'Scan is not paused' });
    }
    
    // Update scan status
    scans[scanIndex].status = 'In Progress';
    
    res.json(scans[scanIndex]);
  } catch (error) {
    req.logger.error('Resume scan error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Stop a scan
router.put('/:id/stop', auth, (req, res) => {
  try {
    const scanIndex = scans.findIndex(s => s.id === req.params.id);
    
    if (scanIndex === -1) {
      return res.status(404).json({ message: 'Scan not found' });
    }
    
    // In a real app, check if the scan belongs to the user
    // if (scans[scanIndex].userId !== req.user.id) {
    //   return res.status(403).json({ message: 'Not authorized' });
    // }
    
    // Check if scan is in progress or paused
    if (scans[scanIndex].status !== 'In Progress' && scans[scanIndex].status !== 'Paused') {
      return res.status(400).json({ message: 'Scan cannot be stopped' });
    }
    
    // Update scan status
    scans[scanIndex].status = 'Stopped';
    
    res.json(scans[scanIndex]);
  } catch (error) {
    req.logger.error('Stop scan error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');

// Mock reports database for demo purposes
const reports = {
  'scan-123': {
    id: 'report-123',
    scanId: 'scan-123',
    target: 'https://example.com',
    date: '2025-04-15',
    summary: {
      'Critical': 3,
      'High': 5,
      'Medium': 8,
      'Low': 4,
      'Info': 2
    },
    executiveSummary: 'The security assessment of example.com revealed several critical and high severity vulnerabilities that require immediate attention. The most concerning issues include SQL injection vulnerabilities in the search functionality and Server-Side Request Forgery (SSRF) in the API endpoints. These vulnerabilities could allow attackers to access sensitive data, execute unauthorized commands, or compromise the system.',
    riskRating: 'High',
    formats: ['html', 'pdf', 'json', 'xml', 'csv'],
    generatedBy: 'SecurScan Security Testing Platform'
  },
  'scan-124': {
    id: 'report-124',
    scanId: 'scan-124',
    target: 'https://test-app.com',
    date: '2025-04-14',
    summary: {
      'Critical': 0,
      'High': 2,
      'Medium': 6,
      'Low': 8,
      'Info': 5
    },
    executiveSummary: 'The security assessment of test-app.com identified several medium and low severity vulnerabilities. While no critical vulnerabilities were found, there are two high severity issues related to Cross-Site Scripting (XSS) that should be addressed promptly. The application generally implements security controls effectively but has room for improvement in input validation and output encoding.',
    riskRating: 'Medium',
    formats: ['html', 'pdf', 'json', 'xml', 'csv'],
    generatedBy: 'SecurScan Security Testing Platform'
  }
};

// Middleware to check if user is authenticated
const auth = (req, res, next) => {
  // In a real app, this would verify the JWT token
  // For demo purposes, we'll just pass through
  next();
};

// Get report for a specific scan
router.get('/scan/:scanId', auth, (req, res) => {
  try {
    const { scanId } = req.params;
    
    // Check if report exists
    if (!reports[scanId]) {
      return res.status(404).json({ message: 'Report not found' });
    }
    
    // Return report
    res.json(reports[scanId]);
  } catch (error) {
    req.logger.error('Get report error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get a specific report by ID
router.get('/:id', auth, (req, res) => {
  try {
    const { id } = req.params;
    
    // Find report
    let foundReport = null;
    
    for (const scanId in reports) {
      if (reports[scanId].id === id) {
        foundReport = reports[scanId];
        break;
      }
    }
    
    if (!foundReport) {
      return res.status(404).json({ message: 'Report not found' });
    }
    
    res.json(foundReport);
  } catch (error) {
    req.logger.error('Get report error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Generate a new report for a scan
router.post('/generate/:scanId', auth, (req, res) => {
  try {
    const { scanId } = req.params;
    const { format } = req.body;
    
    // Check if scan exists (in a real app, this would check the scans database)
    // For demo purposes, we'll just check if we have a report for this scan
    if (!reports[scanId]) {
      // Create a new report with mock data
      reports[scanId] = {
        id: `report-${uuidv4()}`,
        scanId,
        target: `https://example-${scanId}.com`,
        date: new Date().toISOString().split('T')[0],
        summary: {
          'Critical': Math.floor(Math.random() * 3),
          'High': Math.floor(Math.random() * 5),
          'Medium': Math.floor(Math.random() * 8),
          'Low': Math.floor(Math.random() * 6),
          'Info': Math.floor(Math.random() * 10)
        },
        executiveSummary: `The security assessment of example-${scanId}.com revealed several vulnerabilities of varying severity. The application should implement proper input validation, output encoding, and access controls to mitigate these issues.`,
        riskRating: 'Medium',
        formats: ['html', 'pdf', 'json', 'xml', 'csv'],
        generatedBy: 'SecurScan Security Testing Platform'
      };
    }
    
    // In a real app, this would generate the report in the requested format
    // For demo purposes, we'll just return success
    res.json({
      message: `Report generated in ${format || 'html'} format`,
      report: reports[scanId]
    });
  } catch (error) {
    req.logger.error('Generate report error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Download a report in a specific format
router.get('/:id/download/:format', auth, (req, res) => {
  try {
    const { id, format } = req.params;
    
    // Find report
    let foundReport = null;
    
    for (const scanId in reports) {
      if (reports[scanId].id === id) {
        foundReport = reports[scanId];
        break;
      }
    }
    
    if (!foundReport) {
      return res.status(404).json({ message: 'Report not found' });
    }
    
    // Check if format is supported
    if (!foundReport.formats.includes(format)) {
      return res.status(400).json({ message: `Format ${format} not supported` });
    }
    
    // In a real app, this would generate and return the report file
    // For demo purposes, we'll just return a success message
    res.json({
      message: `Report ${id} downloaded in ${format} format`,
      downloadUrl: `/api/reports/${id}/files/${format}`
    });
  } catch (error) {
    req.logger.error('Download report error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all reports for the authenticated user
router.get('/', auth, (req, res) => {
  try {
    // In a real app, this would filter by userId from the JWT token
    // For demo purposes, return all reports
    const allReports = Object.values(reports);
    
    res.json(allReports);
  } catch (error) {
    req.logger.error('Get all reports error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete a report
router.delete('/:id', auth, (req, res) => {
  try {
    const { id } = req.params;
    
    // Find report
    let foundScanId = null;
    
    for (const scanId in reports) {
      if (reports[scanId].id === id) {
        foundScanId = scanId;
        break;
      }
    }
    
    if (!foundScanId) {
      return res.status(404).json({ message: 'Report not found' });
    }
    
    // Delete report
    delete reports[foundScanId];
    
    res.json({ message: 'Report deleted' });
  } catch (error) {
    req.logger.error('Delete report error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;

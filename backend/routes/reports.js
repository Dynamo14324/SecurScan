const express = require('express');
const router = express.Router();

// Mock reports data for demo purposes
const reports = [
  {
    id: '1',
    scanId: '1',
    name: 'Main Website Security Report',
    format: 'pdf',
    createdAt: '2025-04-15 10:15:22',
    status: 'Completed',
    downloadUrl: '/reports/download/1'
  },
  {
    id: '2',
    scanId: '2',
    name: 'API Security Assessment',
    format: 'pdf',
    createdAt: '2025-04-14 15:10:45',
    status: 'Completed',
    downloadUrl: '/reports/download/2'
  }
];

// @route   GET api/reports
// @desc    Get all reports
// @access  Private
router.get('/', (req, res) => {
  res.json(reports);
});

// @route   GET api/reports/:id
// @desc    Get report by ID
// @access  Private
router.get('/:id', (req, res) => {
  const report = reports.find(report => report.id === req.params.id);
  
  if (!report) {
    return res.status(404).json({ msg: 'Report not found' });
  }
  
  res.json(report);
});

// @route   POST api/reports/generate
// @desc    Generate a new report
// @access  Private
router.post('/generate', (req, res) => {
  const { scanId, format } = req.body;
  
  if (!scanId) {
    return res.status(400).json({ msg: 'Scan ID is required' });
  }
  
  // Find the scan to get its name
  const scans = [
    { id: '1', name: 'Main Website Scan' },
    { id: '2', name: 'API Security Test' },
    { id: '3', name: 'Development Server Scan' }
  ];
  
  const scan = scans.find(scan => scan.id === scanId);
  
  if (!scan) {
    return res.status(404).json({ msg: 'Scan not found' });
  }
  
  const newReport = {
    id: (reports.length + 1).toString(),
    scanId,
    name: `${scan.name} Security Report`,
    format: format || 'pdf',
    createdAt: new Date().toISOString().replace('T', ' ').substring(0, 19),
    status: 'Completed',
    downloadUrl: `/reports/download/${reports.length + 1}`
  };
  
  reports.push(newReport);
  
  res.status(201).json(newReport);
});

// @route   GET api/reports/download/:id
// @desc    Download a report
// @access  Private
router.get('/download/:id', (req, res) => {
  const report = reports.find(report => report.id === req.params.id);
  
  if (!report) {
    return res.status(404).json({ msg: 'Report not found' });
  }
  
  // In a real app, this would generate and return the actual report file
  // For demo purposes, we'll just return a success message
  res.json({ 
    success: true, 
    message: 'Report download initiated',
    report
  });
});

module.exports = router;

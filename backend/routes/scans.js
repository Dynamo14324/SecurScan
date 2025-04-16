const express = require('express');
const router = express.Router();

// Mock scans data for demo purposes
const scans = [
  {
    id: '1',
    name: 'Main Website Scan',
    target: 'https://example.com',
    date: '2025-04-15',
    status: 'Completed',
    duration: '45 minutes',
    startTime: '2025-04-15 09:15:22',
    endTime: '2025-04-15 10:00:37',
    scanType: 'Full Scan',
    vulnerabilities: {
      critical: 2,
      high: 3,
      medium: 5,
      low: 8
    }
  },
  {
    id: '2',
    name: 'API Security Test',
    target: 'https://api.example.com',
    date: '2025-04-14',
    status: 'Completed',
    duration: '32 minutes',
    startTime: '2025-04-14 14:22:10',
    endTime: '2025-04-14 14:54:45',
    scanType: 'API Scan',
    vulnerabilities: {
      critical: 1,
      high: 4,
      medium: 7,
      low: 3
    }
  },
  {
    id: '3',
    name: 'Development Server Scan',
    target: 'https://dev.example.com',
    date: '2025-04-13',
    status: 'In Progress',
    duration: '15 minutes',
    startTime: '2025-04-13 11:45:30',
    endTime: null,
    scanType: 'Quick Scan',
    vulnerabilities: {
      critical: 0,
      high: 2,
      medium: 3,
      low: 0
    }
  }
];

// @route   GET api/scans
// @desc    Get all scans
// @access  Private
router.get('/', (req, res) => {
  res.json(scans);
});

// @route   GET api/scans/:id
// @desc    Get scan by ID
// @access  Private
router.get('/:id', (req, res) => {
  const scan = scans.find(scan => scan.id === req.params.id);
  
  if (!scan) {
    return res.status(404).json({ msg: 'Scan not found' });
  }
  
  res.json(scan);
});

// @route   POST api/scans
// @desc    Create a new scan
// @access  Private
router.post('/', (req, res) => {
  const { name, target, scanType, scanOptions } = req.body;
  
  if (!name || !target) {
    return res.status(400).json({ msg: 'Name and target URL are required' });
  }
  
  const newScan = {
    id: (scans.length + 1).toString(),
    name,
    target,
    date: new Date().toISOString().split('T')[0],
    status: 'In Progress',
    duration: '0 minutes',
    startTime: new Date().toISOString().replace('T', ' ').substring(0, 19),
    endTime: null,
    scanType: scanType || 'Full Scan',
    vulnerabilities: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    },
    scanOptions
  };
  
  scans.push(newScan);
  
  res.status(201).json(newScan);
});

// @route   PUT api/scans/:id
// @desc    Update scan status
// @access  Private
router.put('/:id', (req, res) => {
  const scan = scans.find(scan => scan.id === req.params.id);
  
  if (!scan) {
    return res.status(404).json({ msg: 'Scan not found' });
  }
  
  const { status } = req.body;
  
  if (status) {
    scan.status = status;
    
    if (status === 'Completed' && !scan.endTime) {
      scan.endTime = new Date().toISOString().replace('T', ' ').substring(0, 19);
      
      // Calculate duration
      const start = new Date(scan.startTime);
      const end = new Date(scan.endTime);
      const durationMinutes = Math.round((end - start) / 60000);
      scan.duration = `${durationMinutes} minutes`;
      
      // Generate random vulnerabilities for demo
      scan.vulnerabilities = {
        critical: Math.floor(Math.random() * 3),
        high: Math.floor(Math.random() * 5),
        medium: Math.floor(Math.random() * 8),
        low: Math.floor(Math.random() * 10)
      };
    }
  }
  
  res.json(scan);
});

// @route   DELETE api/scans/:id
// @desc    Delete a scan
// @access  Private
router.delete('/:id', (req, res) => {
  const scanIndex = scans.findIndex(scan => scan.id === req.params.id);
  
  if (scanIndex === -1) {
    return res.status(404).json({ msg: 'Scan not found' });
  }
  
  scans.splice(scanIndex, 1);
  
  res.json({ msg: 'Scan removed' });
});

module.exports = router;

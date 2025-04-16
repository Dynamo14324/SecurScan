const express = require('express');
const router = express.Router();

// Mock vulnerabilities data for demo purposes
const vulnerabilities = [
  {
    id: '1',
    scanId: '1',
    name: 'SQL Injection',
    severity: 'critical',
    location: '/search.php?q=',
    description: 'The application is vulnerable to SQL injection attacks through the search parameter.',
    evidence: "The application returned database error messages when the input ' OR 1=1 -- was submitted.",
    remediation: 'Use parameterized queries or prepared statements to prevent SQL injection attacks.',
    cvss: 9.8,
    cwe: 'CWE-89',
    status: 'Open',
    discoveredAt: '2025-04-15 09:32:15'
  },
  {
    id: '2',
    scanId: '1',
    name: 'Cross-Site Scripting (XSS)',
    severity: 'high',
    location: '/comment.php?message=',
    description: 'The application is vulnerable to reflected XSS attacks through the message parameter.',
    evidence: "The application executed JavaScript when the input <script>alert('XSS')</script> was submitted.",
    remediation: 'Implement proper output encoding and content security policy.',
    cvss: 7.5,
    cwe: 'CWE-79',
    status: 'Open',
    discoveredAt: '2025-04-15 09:45:22'
  },
  {
    id: '3',
    scanId: '1',
    name: 'Insecure Direct Object Reference',
    severity: 'medium',
    location: '/profile.php?id=',
    description: 'The application allows unauthorized access to user profiles by manipulating the id parameter.',
    evidence: 'Changing the id parameter to another value displayed information for a different user without proper authorization.',
    remediation: 'Implement proper access controls and validate user permissions before displaying sensitive information.',
    cvss: 5.5,
    cwe: 'CWE-639',
    status: 'Open',
    discoveredAt: '2025-04-15 09:52:37'
  },
  {
    id: '4',
    scanId: '2',
    name: 'API Key Exposure',
    severity: 'critical',
    location: '/api/v1/config',
    description: 'The API exposes sensitive API keys in the configuration endpoint.',
    evidence: 'The response from the /api/v1/config endpoint contains plaintext API keys and secrets.',
    remediation: 'Remove sensitive information from API responses and implement proper authentication for configuration endpoints.',
    cvss: 9.1,
    cwe: 'CWE-312',
    status: 'Open',
    discoveredAt: '2025-04-14 14:30:12'
  }
];

// @route   GET api/vulnerabilities
// @desc    Get all vulnerabilities
// @access  Private
router.get('/', (req, res) => {
  res.json(vulnerabilities);
});

// @route   GET api/vulnerabilities/:id
// @desc    Get vulnerability by ID
// @access  Private
router.get('/:id', (req, res) => {
  const vulnerability = vulnerabilities.find(vuln => vuln.id === req.params.id);
  
  if (!vulnerability) {
    return res.status(404).json({ msg: 'Vulnerability not found' });
  }
  
  res.json(vulnerability);
});

// @route   GET api/vulnerabilities/scan/:scanId
// @desc    Get vulnerabilities by scan ID
// @access  Private
router.get('/scan/:scanId', (req, res) => {
  const scanVulnerabilities = vulnerabilities.filter(vuln => vuln.scanId === req.params.scanId);
  res.json(scanVulnerabilities);
});

// @route   PUT api/vulnerabilities/:id
// @desc    Update vulnerability status
// @access  Private
router.put('/:id', (req, res) => {
  const vulnerability = vulnerabilities.find(vuln => vuln.id === req.params.id);
  
  if (!vulnerability) {
    return res.status(404).json({ msg: 'Vulnerability not found' });
  }
  
  const { status, notes } = req.body;
  
  if (status) {
    vulnerability.status = status;
  }
  
  if (notes) {
    vulnerability.notes = notes;
  }
  
  res.json(vulnerability);
});

module.exports = router;

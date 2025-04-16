const express = require('express');
const router = express.Router();

// Mock test cases data for demo purposes
const testCases = [
  {
    id: '1',
    name: 'SQL Injection Test',
    description: 'Test for SQL injection vulnerabilities in input fields',
    category: 'Injection',
    severity: 'High',
    createdAt: '2025-03-10',
    status: 'Active',
    steps: [
      'Identify input fields that might interact with a database',
      'Try entering SQL special characters like single quotes',
      'Test with payloads like \' OR 1=1 --',
      'Check for database error messages or unexpected behavior'
    ]
  },
  {
    id: '2',
    name: 'XSS Detection',
    description: 'Test for Cross-Site Scripting vulnerabilities',
    category: 'Injection',
    severity: 'High',
    createdAt: '2025-03-12',
    status: 'Active',
    steps: [
      'Identify input fields that output content to web pages',
      'Test with simple script tags like <script>alert("XSS")</script>',
      'Try different encoding techniques to bypass filters',
      'Check if the script executes in the browser'
    ]
  },
  {
    id: '3',
    name: 'CSRF Token Validation',
    description: 'Test for proper CSRF token implementation',
    category: 'Session Management',
    severity: 'Medium',
    createdAt: '2025-03-15',
    status: 'Active',
    steps: [
      'Identify forms and state-changing operations',
      'Check if CSRF tokens are present in forms',
      'Try submitting forms with missing or invalid tokens',
      'Verify that the application rejects requests without valid tokens'
    ]
  }
];

// @route   GET api/test-cases
// @desc    Get all test cases
// @access  Private
router.get('/', (req, res) => {
  res.json(testCases);
});

// @route   GET api/test-cases/:id
// @desc    Get test case by ID
// @access  Private
router.get('/:id', (req, res) => {
  const testCase = testCases.find(tc => tc.id === req.params.id);
  
  if (!testCase) {
    return res.status(404).json({ msg: 'Test case not found' });
  }
  
  res.json(testCase);
});

// @route   POST api/test-cases
// @desc    Create a new test case
// @access  Private
router.post('/', (req, res) => {
  const { name, description, category, severity, steps } = req.body;
  
  if (!name || !category) {
    return res.status(400).json({ msg: 'Name and category are required' });
  }
  
  const newTestCase = {
    id: (testCases.length + 1).toString(),
    name,
    description: description || '',
    category,
    severity: severity || 'Medium',
    createdAt: new Date().toISOString().split('T')[0],
    status: 'Active',
    steps: steps || []
  };
  
  testCases.push(newTestCase);
  
  res.status(201).json(newTestCase);
});

// @route   PUT api/test-cases/:id
// @desc    Update test case
// @access  Private
router.put('/:id', (req, res) => {
  const testCase = testCases.find(tc => tc.id === req.params.id);
  
  if (!testCase) {
    return res.status(404).json({ msg: 'Test case not found' });
  }
  
  const { name, description, category, severity, status, steps } = req.body;
  
  if (name) testCase.name = name;
  if (description) testCase.description = description;
  if (category) testCase.category = category;
  if (severity) testCase.severity = severity;
  if (status) testCase.status = status;
  if (steps) testCase.steps = steps;
  
  res.json(testCase);
});

// @route   DELETE api/test-cases/:id
// @desc    Delete test case
// @access  Private
router.delete('/:id', (req, res) => {
  const testCaseIndex = testCases.findIndex(tc => tc.id === req.params.id);
  
  if (testCaseIndex === -1) {
    return res.status(404).json({ msg: 'Test case not found' });
  }
  
  testCases.splice(testCaseIndex, 1);
  
  res.json({ msg: 'Test case removed' });
});

module.exports = router;

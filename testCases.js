const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const TestCaseManager = require('../../testing-env/test-case-manager');

// Initialize test case manager
const testCaseManager = new TestCaseManager({
  baseDir: process.env.TEST_CASES_DIR || '/home/ubuntu/SecurScan/testing-env/test-cases'
});

// Middleware to check if user is authenticated
const auth = (req, res, next) => {
  // In a real app, this would verify the JWT token
  // For demo purposes, we'll just pass through
  next();
};

// Get all test cases
router.get('/', auth, (req, res) => {
  try {
    const testCases = testCaseManager.getAllTestCases();
    res.json(testCases);
  } catch (error) {
    req.logger.error('Get test cases error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get test cases by category
router.get('/category/:category', auth, (req, res) => {
  try {
    const { category } = req.params;
    const testCases = testCaseManager.getTestCasesByCategory(category);
    res.json(testCases);
  } catch (error) {
    req.logger.error('Get test cases by category error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get a specific test case by ID
router.get('/:id', auth, (req, res) => {
  try {
    const { id } = req.params;
    const testCase = testCaseManager.getTestCaseById(id);
    
    if (!testCase) {
      return res.status(404).json({ message: 'Test case not found' });
    }
    
    res.json(testCase);
  } catch (error) {
    req.logger.error('Get test case error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create a new test case
router.post('/', auth, (req, res) => {
  try {
    const testCaseData = req.body;
    
    // Validate required fields
    if (!testCaseData.name || !testCaseData.category) {
      return res.status(400).json({ message: 'Name and category are required' });
    }
    
    // Create test case
    const newTestCase = testCaseManager.createTestCase(testCaseData);
    
    res.status(201).json(newTestCase);
  } catch (error) {
    req.logger.error('Create test case error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create a test case from a template
router.post('/from-template', auth, (req, res) => {
  try {
    const { templateName, overrides } = req.body;
    
    // Validate required fields
    if (!templateName) {
      return res.status(400).json({ message: 'Template name is required' });
    }
    
    // Create test case from template
    const newTestCase = testCaseManager.createTestCaseFromTemplate(templateName, overrides);
    
    res.status(201).json(newTestCase);
  } catch (error) {
    req.logger.error('Create test case from template error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update a test case
router.put('/:id', auth, (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    
    // Update test case
    const updatedTestCase = testCaseManager.updateTestCase(id, updates);
    
    res.json(updatedTestCase);
  } catch (error) {
    req.logger.error('Update test case error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete a test case
router.delete('/:id', auth, (req, res) => {
  try {
    const { id } = req.params;
    
    // Delete test case
    const success = testCaseManager.deleteTestCase(id);
    
    if (!success) {
      return res.status(404).json({ message: 'Test case not found' });
    }
    
    res.json({ message: 'Test case deleted' });
  } catch (error) {
    req.logger.error('Delete test case error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get test case history
router.get('/:id/history', auth, (req, res) => {
  try {
    const { id } = req.params;
    const history = testCaseManager.getTestCaseHistory(id);
    
    res.json(history);
  } catch (error) {
    req.logger.error('Get test case history error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Restore a previous version of a test case
router.post('/:id/restore/:version', auth, (req, res) => {
  try {
    const { id, version } = req.params;
    
    // Restore test case version
    const restoredTestCase = testCaseManager.restoreTestCaseVersion(id, parseInt(version));
    
    res.json(restoredTestCase);
  } catch (error) {
    req.logger.error('Restore test case version error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Search test cases
router.post('/search', auth, (req, res) => {
  try {
    const criteria = req.body;
    
    // Search test cases
    const results = testCaseManager.searchTestCases(criteria);
    
    res.json(results);
  } catch (error) {
    req.logger.error('Search test cases error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Export test cases
router.post('/export', auth, (req, res) => {
  try {
    const { testCases, format } = req.body;
    
    // Validate required fields
    if (!testCases || !Array.isArray(testCases)) {
      return res.status(400).json({ message: 'Test cases array is required' });
    }
    
    // In a real app, this would generate and return the export file
    // For demo purposes, we'll just return a success message
    
    res.json({
      message: `${testCases.length} test cases exported in ${format || 'json'} format`,
      exportUrl: `/api/test-cases/exports/${uuidv4()}.${format || 'json'}`
    });
  } catch (error) {
    req.logger.error('Export test cases error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Import test cases
router.post('/import', auth, (req, res) => {
  try {
    const { importData } = req.body;
    
    // Validate required fields
    if (!importData || !importData.test_cases || !Array.isArray(importData.test_cases)) {
      return res.status(400).json({ message: 'Valid import data is required' });
    }
    
    // In a real app, this would process the import file
    // For demo purposes, we'll just return a success message
    
    res.json({
      message: `${importData.test_cases.length} test cases imported successfully`,
      importedCount: importData.test_cases.length
    });
  } catch (error) {
    req.logger.error('Import test cases error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;

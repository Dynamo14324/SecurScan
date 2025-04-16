// Mock implementation of the test case manager for testing purposes
class TestCaseManager {
  constructor(options = {}) {
    this.baseDir = options.baseDir || '/home/ubuntu/SecurScan/testing-env/test-cases';
    this.testCases = [
      {
        id: 'tc-001',
        name: 'SQL Injection Test Case',
        category: 'sql-injection',
        description: 'Test case for detecting SQL injection vulnerabilities',
        steps: [
          'Submit payload to login form',
          'Check for database error messages',
          'Verify unauthorized access'
        ],
        payloads: [
          "' OR 1=1 --",
          "admin' --",
          "1' OR '1'='1"
        ],
        expectedResults: 'Application should reject the payloads and not expose database errors',
        created: '2025-04-01',
        updated: '2025-04-15',
        version: 2
      },
      {
        id: 'tc-002',
        name: 'XSS Test Case',
        category: 'xss',
        description: 'Test case for detecting cross-site scripting vulnerabilities',
        steps: [
          'Submit payload to comment form',
          'Check if script executes',
          'Verify payload reflection'
        ],
        payloads: [
          "<script>alert('XSS')</script>",
          "<img src=x onerror=alert('XSS')>",
          "<body onload=alert('XSS')>"
        ],
        expectedResults: 'Application should sanitize input and prevent script execution',
        created: '2025-04-02',
        updated: '2025-04-14',
        version: 1
      },
      {
        id: 'tc-003',
        name: 'CSRF Test Case',
        category: 'csrf',
        description: 'Test case for detecting cross-site request forgery vulnerabilities',
        steps: [
          'Create forged request',
          'Submit request from different origin',
          'Verify if action is performed'
        ],
        payloads: [
          '<form action="https://example.com/change-password" method="POST">',
          '<iframe src="https://example.com/perform-action" style="display:none">',
          '<img src="https://example.com/api/delete?id=123">'
        ],
        expectedResults: 'Application should validate CSRF tokens and reject forged requests',
        created: '2025-04-03',
        updated: '2025-04-13',
        version: 3
      }
    ];
    
    this.templates = {
      'sql-injection': {
        name: 'SQL Injection Template',
        category: 'sql-injection',
        description: 'Template for SQL injection test cases',
        steps: [
          'Submit payload to target input',
          'Check for database error messages',
          'Verify unauthorized access'
        ],
        payloads: [
          "' OR 1=1 --",
          "admin' --",
          "1' OR '1'='1"
        ],
        expectedResults: 'Application should reject the payloads and not expose database errors'
      },
      'xss': {
        name: 'XSS Template',
        category: 'xss',
        description: 'Template for XSS test cases',
        steps: [
          'Submit payload to target input',
          'Check if script executes',
          'Verify payload reflection'
        ],
        payloads: [
          "<script>alert('XSS')</script>",
          "<img src=x onerror=alert('XSS')>",
          "<body onload=alert('XSS')>"
        ],
        expectedResults: 'Application should sanitize input and prevent script execution'
      }
    };
    
    this.history = {
      'tc-001': [
        {
          version: 1,
          timestamp: '2025-04-01T10:00:00Z',
          changes: 'Initial creation'
        },
        {
          version: 2,
          timestamp: '2025-04-15T14:30:00Z',
          changes: 'Updated payloads and steps'
        }
      ],
      'tc-002': [
        {
          version: 1,
          timestamp: '2025-04-02T11:15:00Z',
          changes: 'Initial creation'
        }
      ],
      'tc-003': [
        {
          version: 1,
          timestamp: '2025-04-03T09:45:00Z',
          changes: 'Initial creation'
        },
        {
          version: 2,
          timestamp: '2025-04-10T16:20:00Z',
          changes: 'Updated steps'
        },
        {
          version: 3,
          timestamp: '2025-04-13T13:10:00Z',
          changes: 'Added new payloads'
        }
      ]
    };
  }
  
  getAllTestCases() {
    return this.testCases;
  }
  
  getTestCasesByCategory(category) {
    return this.testCases.filter(tc => tc.category === category);
  }
  
  getTestCaseById(id) {
    return this.testCases.find(tc => tc.id === id);
  }
  
  createTestCase(testCaseData) {
    const newTestCase = {
      id: `tc-${Date.now().toString().substr(-6)}`,
      ...testCaseData,
      created: new Date().toISOString().split('T')[0],
      updated: new Date().toISOString().split('T')[0],
      version: 1
    };
    
    this.testCases.push(newTestCase);
    this.history[newTestCase.id] = [
      {
        version: 1,
        timestamp: new Date().toISOString(),
        changes: 'Initial creation'
      }
    ];
    
    return newTestCase;
  }
  
  createTestCaseFromTemplate(templateName, overrides = {}) {
    const template = this.templates[templateName];
    
    if (!template) {
      throw new Error(`Template "${templateName}" not found`);
    }
    
    return this.createTestCase({
      ...template,
      ...overrides
    });
  }
  
  updateTestCase(id, updates) {
    const index = this.testCases.findIndex(tc => tc.id === id);
    
    if (index === -1) {
      throw new Error(`Test case "${id}" not found`);
    }
    
    const testCase = this.testCases[index];
    const updatedTestCase = {
      ...testCase,
      ...updates,
      updated: new Date().toISOString().split('T')[0],
      version: testCase.version + 1
    };
    
    this.testCases[index] = updatedTestCase;
    
    if (!this.history[id]) {
      this.history[id] = [];
    }
    
    this.history[id].push({
      version: updatedTestCase.version,
      timestamp: new Date().toISOString(),
      changes: 'Updated test case'
    });
    
    return updatedTestCase;
  }
  
  deleteTestCase(id) {
    const index = this.testCases.findIndex(tc => tc.id === id);
    
    if (index === -1) {
      return false;
    }
    
    this.testCases.splice(index, 1);
    delete this.history[id];
    
    return true;
  }
  
  getTestCaseHistory(id) {
    return this.history[id] || [];
  }
  
  restoreTestCaseVersion(id, version) {
    // In a real implementation, this would restore from version control
    // For mock purposes, we'll just return the current test case
    const testCase = this.getTestCaseById(id);
    
    if (!testCase) {
      throw new Error(`Test case "${id}" not found`);
    }
    
    return {
      ...testCase,
      version: version,
      updated: new Date().toISOString().split('T')[0],
      restored: true
    };
  }
  
  searchTestCases(criteria) {
    let results = [...this.testCases];
    
    if (criteria.category) {
      results = results.filter(tc => tc.category === criteria.category);
    }
    
    if (criteria.name) {
      const searchTerm = criteria.name.toLowerCase();
      results = results.filter(tc => tc.name.toLowerCase().includes(searchTerm));
    }
    
    if (criteria.description) {
      const searchTerm = criteria.description.toLowerCase();
      results = results.filter(tc => tc.description.toLowerCase().includes(searchTerm));
    }
    
    return results;
  }
}

module.exports = TestCaseManager;

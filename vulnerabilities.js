const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');

// Mock vulnerability database for demo purposes
const vulnerabilities = {
  'scan-123': [
    {
      id: 'vuln-001',
      name: 'SQL Injection',
      severity: 'Critical',
      location: 'https://example.com/search?q=test',
      parameter: 'q',
      description: 'The application is vulnerable to SQL injection attacks through the search parameter. An attacker can manipulate the SQL query to access unauthorized data or perform unauthorized actions.',
      evidence: "The application returned database error messages when the following payload was submitted: q=test' OR 1=1 --",
      cvss: 9.8,
      cwe: 'CWE-89',
      remediation: 'Use parameterized queries or prepared statements to prevent SQL injection. Implement input validation and sanitization.',
      poc: "GET /search?q=test'%20OR%201=1%20-- HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\nAccept: text/html,application/xhtml+xml",
      verified: true
    },
    {
      id: 'vuln-002',
      name: 'Cross-Site Scripting (XSS)',
      severity: 'High',
      location: 'https://example.com/comment',
      parameter: 'message',
      description: 'The application is vulnerable to stored Cross-Site Scripting (XSS) attacks in the comment section. An attacker can inject malicious JavaScript code that will be executed in the context of other users browsing the page.',
      evidence: 'The application rendered the following payload without sanitization: <script>alert(1)</script>',
      cvss: 8.2,
      cwe: 'CWE-79',
      remediation: 'Implement proper output encoding and input validation. Consider using a Content Security Policy (CSP) to mitigate XSS attacks.',
      poc: "POST /comment HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nmessage=<script>alert(document.cookie)</script>",
      verified: true
    },
    {
      id: 'vuln-003',
      name: 'Cross-Site Request Forgery (CSRF)',
      severity: 'Medium',
      location: 'https://example.com/account/settings',
      parameter: 'N/A',
      description: 'The application does not implement CSRF tokens for sensitive operations. An attacker can trick a user into performing unwanted actions on the application while the user is authenticated.',
      evidence: 'The application accepted form submissions without validating any CSRF token.',
      cvss: 6.5,
      cwe: 'CWE-352',
      remediation: 'Implement anti-CSRF tokens for all state-changing operations. Validate the token on the server side before processing the request.',
      poc: '<form action="https://example.com/account/settings" method="POST">\n  <input type="hidden" name="email" value="attacker@evil.com" />\n  <input type="submit" value="Win a Prize" />\n</form>',
      verified: true
    },
    {
      id: 'vuln-004',
      name: 'Server-Side Request Forgery (SSRF)',
      severity: 'Critical',
      location: 'https://example.com/api/fetch-data',
      parameter: 'url',
      description: 'The application is vulnerable to Server-Side Request Forgery (SSRF) attacks. An attacker can make the server perform requests to internal resources that should not be accessible.',
      evidence: 'The application made a request to an internal IP address when provided with the URL parameter: url=http://localhost:8080/admin',
      cvss: 9.1,
      cwe: 'CWE-918',
      remediation: 'Implement a whitelist of allowed domains and protocols. Validate and sanitize user input before making server-side requests.',
      poc: "GET /api/fetch-data?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0",
      verified: true
    },
    {
      id: 'vuln-005',
      name: 'Insecure Direct Object Reference (IDOR)',
      severity: 'High',
      location: 'https://example.com/api/users/123/profile',
      parameter: 'user_id',
      description: 'The application is vulnerable to Insecure Direct Object Reference (IDOR) attacks. An attacker can access or modify resources belonging to other users by manipulating the user_id parameter.',
      evidence: 'The application returned sensitive information for user_id=456 when authenticated as user_id=123.',
      cvss: 7.5,
      cwe: 'CWE-639',
      remediation: 'Implement proper access control checks. Verify that the authenticated user has permission to access the requested resource.',
      poc: "GET /api/users/456/profile HTTP/1.1\nHost: example.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      verified: true
    }
  ],
  'new-scan-123': [
    {
      id: 'vuln-001',
      name: 'SQL Injection',
      severity: 'Critical',
      location: 'https://example.com/search?q=test',
      parameter: 'q',
      description: 'The application is vulnerable to SQL injection attacks through the search parameter. An attacker can manipulate the SQL query to access unauthorized data or perform unauthorized actions.',
      evidence: "The application returned database error messages when the following payload was submitted: q=test' OR 1=1 --",
      cvss: 9.8,
      cwe: 'CWE-89',
      remediation: 'Use parameterized queries or prepared statements to prevent SQL injection. Implement input validation and sanitization.',
      poc: "GET /search?q=test'%20OR%201=1%20-- HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\nAccept: text/html,application/xhtml+xml",
      verified: true
    },
    {
      id: 'vuln-002',
      name: 'Cross-Site Scripting (XSS)',
      severity: 'High',
      location: 'https://example.com/comment',
      parameter: 'message',
      description: 'The application is vulnerable to stored Cross-Site Scripting (XSS) attacks in the comment section. An attacker can inject malicious JavaScript code that will be executed in the context of other users browsing the page.',
      evidence: 'The application rendered the following payload without sanitization: <script>alert(1)</script>',
      cvss: 8.2,
      cwe: 'CWE-79',
      remediation: 'Implement proper output encoding and input validation. Consider using a Content Security Policy (CSP) to mitigate XSS attacks.',
      poc: "POST /comment HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nmessage=<script>alert(document.cookie)</script>",
      verified: true
    },
    {
      id: 'vuln-003',
      name: 'Cross-Site Request Forgery (CSRF)',
      severity: 'Medium',
      location: 'https://example.com/account/settings',
      parameter: 'N/A',
      description: 'The application does not implement CSRF tokens for sensitive operations. An attacker can trick a user into performing unwanted actions on the application while the user is authenticated.',
      evidence: 'The application accepted form submissions without validating any CSRF token.',
      cvss: 6.5,
      cwe: 'CWE-352',
      remediation: 'Implement anti-CSRF tokens for all state-changing operations. Validate the token on the server side before processing the request.',
      poc: '<form action="https://example.com/account/settings" method="POST">\n  <input type="hidden" name="email" value="attacker@evil.com" />\n  <input type="submit" value="Win a Prize" />\n</form>',
      verified: true
    }
  ]
};

// Middleware to check if user is authenticated
const auth = (req, res, next) => {
  // In a real app, this would verify the JWT token
  // For demo purposes, we'll just pass through
  next();
};

// Get all vulnerabilities for a specific scan
router.get('/scan/:scanId', auth, (req, res) => {
  try {
    const { scanId } = req.params;
    
    // Check if scan exists
    if (!vulnerabilities[scanId]) {
      return res.status(404).json({ message: 'Scan not found or no vulnerabilities detected' });
    }
    
    // Return vulnerabilities for the scan
    res.json(vulnerabilities[scanId]);
  } catch (error) {
    req.logger.error('Get vulnerabilities error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get a specific vulnerability by ID
router.get('/:id', auth, (req, res) => {
  try {
    const { id } = req.params;
    
    // Find vulnerability across all scans
    let foundVulnerability = null;
    
    for (const scanId in vulnerabilities) {
      const vulnerability = vulnerabilities[scanId].find(v => v.id === id);
      if (vulnerability) {
        foundVulnerability = vulnerability;
        break;
      }
    }
    
    if (!foundVulnerability) {
      return res.status(404).json({ message: 'Vulnerability not found' });
    }
    
    res.json(foundVulnerability);
  } catch (error) {
    req.logger.error('Get vulnerability error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify a vulnerability
router.post('/:id/verify', auth, (req, res) => {
  try {
    const { id } = req.params;
    
    // Find vulnerability across all scans
    let foundVulnerability = null;
    let scanId = null;
    let vulnerabilityIndex = -1;
    
    for (const sid in vulnerabilities) {
      const index = vulnerabilities[sid].findIndex(v => v.id === id);
      if (index !== -1) {
        foundVulnerability = vulnerabilities[sid][index];
        scanId = sid;
        vulnerabilityIndex = index;
        break;
      }
    }
    
    if (!foundVulnerability) {
      return res.status(404).json({ message: 'Vulnerability not found' });
    }
    
    // In a real app, this would trigger a verification scan
    // For demo purposes, we'll just update the verified status
    
    // Simulate verification process
    setTimeout(() => {
      vulnerabilities[scanId][vulnerabilityIndex].verified = true;
    }, 2000);
    
    res.json({ message: 'Verification started', status: 'in_progress' });
  } catch (error) {
    req.logger.error('Verify vulnerability error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update vulnerability details (e.g., add notes, change severity)
router.put('/:id', auth, (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    
    // Find vulnerability across all scans
    let foundVulnerability = null;
    let scanId = null;
    let vulnerabilityIndex = -1;
    
    for (const sid in vulnerabilities) {
      const index = vulnerabilities[sid].findIndex(v => v.id === id);
      if (index !== -1) {
        foundVulnerability = vulnerabilities[sid][index];
        scanId = sid;
        vulnerabilityIndex = index;
        break;
      }
    }
    
    if (!foundVulnerability) {
      return res.status(404).json({ message: 'Vulnerability not found' });
    }
    
    // Update vulnerability
    vulnerabilities[scanId][vulnerabilityIndex] = {
      ...foundVulnerability,
      ...updates,
      id // Ensure ID doesn't change
    };
    
    res.json(vulnerabilities[scanId][vulnerabilityIndex]);
  } catch (error) {
    req.logger.error('Update vulnerability error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get vulnerability statistics
router.get('/stats/summary', auth, (req, res) => {
  try {
    // Calculate statistics across all scans
    const stats = {
      total: 0,
      bySeverity: {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0,
        Info: 0
      },
      byType: {},
      verified: 0,
      unverified: 0
    };
    
    // Process all vulnerabilities
    for (const scanId in vulnerabilities) {
      for (const vulnerability of vulnerabilities[scanId]) {
        // Increment total
        stats.total++;
        
        // Increment by severity
        stats.bySeverity[vulnerability.severity]++;
        
        // Increment by type
        if (!stats.byType[vulnerability.name]) {
          stats.byType[vulnerability.name] = 0;
        }
        stats.byType[vulnerability.name]++;
        
        // Increment verified/unverified
        if (vulnerability.verified) {
          stats.verified++;
        } else {
          stats.unverified++;
        }
      }
    }
    
    res.json(stats);
  } catch (error) {
    req.logger.error('Get vulnerability stats error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;

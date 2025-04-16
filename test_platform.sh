#!/bin/bash

# Test script for SecurScan security testing platform
# This script tests the functionality of the integrated platform

echo "Starting SecurScan platform tests..."
echo "====================================="

# Create test directory
TEST_DIR="/home/ubuntu/SecurScan/tests"
mkdir -p $TEST_DIR

# Function to log test results
log_test() {
  local test_name=$1
  local status=$2
  local details=$3
  
  echo "[$status] $test_name: $details" | tee -a $TEST_DIR/test_results.log
}

# Test backend server startup
echo "Testing backend server startup..."
cd /home/ubuntu/SecurScan/backend
node src/server.js &
SERVER_PID=$!
sleep 2

if ps -p $SERVER_PID > /dev/null; then
  log_test "Backend Server Startup" "PASS" "Server started successfully with PID $SERVER_PID"
else
  log_test "Backend Server Startup" "FAIL" "Server failed to start"
  exit 1
fi

# Test API endpoints
echo "Testing API endpoints..."

# Function to test API endpoint
test_endpoint() {
  local endpoint=$1
  local method=$2
  local expected_status=$3
  local description=$4
  
  response=$(curl -s -o /dev/null -w "%{http_code}" -X $method http://localhost:5000$endpoint)
  
  if [ "$response" -eq "$expected_status" ]; then
    log_test "API Endpoint: $endpoint ($method)" "PASS" "$description - Status: $response"
    return 0
  else
    log_test "API Endpoint: $endpoint ($method)" "FAIL" "$description - Expected: $expected_status, Got: $response"
    return 1
  fi
}

# Test authentication endpoints
test_endpoint "/api/auth/login" "POST" 401 "Login endpoint (unauthorized without credentials)"
test_endpoint "/api/auth/register" "POST" 400 "Register endpoint (bad request without data)"
test_endpoint "/api/auth/me" "GET" 401 "Get current user (unauthorized without token)"

# Test scan endpoints
test_endpoint "/api/scans" "GET" 200 "Get all scans"
test_endpoint "/api/scans/scan-123" "GET" 200 "Get specific scan"
test_endpoint "/api/scans/invalid-id" "GET" 404 "Get non-existent scan"

# Test vulnerability endpoints
test_endpoint "/api/vulnerabilities/scan/scan-123" "GET" 200 "Get vulnerabilities for scan"
test_endpoint "/api/vulnerabilities/scan/invalid-id" "GET" 404 "Get vulnerabilities for non-existent scan"

# Test report endpoints
test_endpoint "/api/reports" "GET" 200 "Get all reports"
test_endpoint "/api/reports/scan/scan-123" "GET" 200 "Get report for scan"

# Test user endpoints
test_endpoint "/api/users" "GET" 200 "Get all users"
test_endpoint "/api/users/1" "GET" 200 "Get specific user"
test_endpoint "/api/users/invalid-id" "GET" 404 "Get non-existent user"

# Test project endpoints
test_endpoint "/api/projects" "GET" 200 "Get all projects"
test_endpoint "/api/projects/proj-001" "GET" 200 "Get specific project"
test_endpoint "/api/projects/invalid-id" "GET" 404 "Get non-existent project"

# Test test case endpoints
test_endpoint "/api/test-cases" "GET" 200 "Get all test cases"

# Test vulnerability detection engine
echo "Testing vulnerability detection engine..."

# Create test script for SQL injection scanner
cat > $TEST_DIR/test_sql_injection.js << 'EOF'
const SQLInjectionScanner = require('../backend/src/modules/sql-injection-scanner');
const scanner = new SQLInjectionScanner();

// Test target
const testTarget = {
  url: 'https://example.com/search',
  parameter: 'q',
  value: 'test'
};

// Test payloads
const testPayloads = [
  "' OR 1=1 --",
  "1' OR '1'='1",
  "1 OR 1=1"
];

// Test detection function
async function testDetection() {
  console.log("Testing SQL Injection detection...");
  
  try {
    // Mock scan function to simulate responses
    scanner.sendRequest = async (url, payload) => {
      // Simulate vulnerable response for the first payload
      if (payload.includes("' OR 1=1 --")) {
        return {
          status: 200,
          body: 'Error: You have an error in your SQL syntax',
          headers: {}
        };
      }
      // Simulate normal response for other payloads
      return {
        status: 200,
        body: 'No results found',
        headers: {}
      };
    };
    
    // Run detection
    const results = await scanner.scan(testTarget, testPayloads);
    
    // Check results
    if (results.vulnerable) {
      console.log("✅ SQL Injection detection working correctly");
      console.log(`Detected vulnerability with payload: ${results.payload}`);
      return true;
    } else {
      console.log("❌ SQL Injection detection failed to identify vulnerability");
      return false;
    }
  } catch (error) {
    console.error("❌ Error testing SQL Injection detection:", error);
    return false;
  }
}

// Run test
testDetection().then(success => {
  process.exit(success ? 0 : 1);
});
EOF

# Run SQL injection test
echo "Running SQL injection scanner test..."
node $TEST_DIR/test_sql_injection.js
if [ $? -eq 0 ]; then
  log_test "SQL Injection Scanner" "PASS" "Scanner correctly identified vulnerabilities"
else
  log_test "SQL Injection Scanner" "FAIL" "Scanner failed to identify vulnerabilities"
fi

# Create test script for XSS scanner
cat > $TEST_DIR/test_xss_scanner.js << 'EOF'
const XSSScanner = require('../backend/src/modules/xss-scanner');
const scanner = new XSSScanner();

// Test target
const testTarget = {
  url: 'https://example.com/comment',
  parameter: 'message',
  value: 'test'
};

// Test payloads
const testPayloads = [
  "<script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
  "<body onload=alert(1)>"
];

// Test detection function
async function testDetection() {
  console.log("Testing XSS detection...");
  
  try {
    // Mock scan function to simulate responses
    scanner.sendRequest = async (url, payload) => {
      // Simulate vulnerable response that reflects the payload
      return {
        status: 200,
        body: `Thank you for your comment: ${payload}`,
        headers: {}
      };
    };
    
    // Run detection
    const results = await scanner.scan(testTarget, testPayloads);
    
    // Check results
    if (results.vulnerable) {
      console.log("✅ XSS detection working correctly");
      console.log(`Detected vulnerability with payload: ${results.payload}`);
      return true;
    } else {
      console.log("❌ XSS detection failed to identify vulnerability");
      return false;
    }
  } catch (error) {
    console.error("❌ Error testing XSS detection:", error);
    return false;
  }
}

// Run test
testDetection().then(success => {
  process.exit(success ? 0 : 1);
});
EOF

# Run XSS scanner test
echo "Running XSS scanner test..."
node $TEST_DIR/test_xss_scanner.js
if [ $? -eq 0 ]; then
  log_test "XSS Scanner" "PASS" "Scanner correctly identified vulnerabilities"
else
  log_test "XSS Scanner" "FAIL" "Scanner failed to identify vulnerabilities"
fi

# Test reporting system
echo "Testing reporting system..."

# Create test script for report generation
cat > $TEST_DIR/test_report_generator.js << 'EOF'
const ReportGenerator = require('../backend/src/core/report-generator');
const generator = new ReportGenerator();

// Test scan data
const testScan = {
  id: 'test-scan-001',
  target: 'https://example.com',
  date: '2025-04-15',
  vulnerabilities: [
    {
      id: 'vuln-001',
      name: 'SQL Injection',
      severity: 'Critical',
      location: 'https://example.com/search?q=test',
      description: 'SQL injection vulnerability in search parameter'
    },
    {
      id: 'vuln-002',
      name: 'Cross-Site Scripting (XSS)',
      severity: 'High',
      location: 'https://example.com/comment',
      description: 'XSS vulnerability in comment form'
    }
  ]
};

// Test report generation
async function testReportGeneration() {
  console.log("Testing report generation...");
  
  try {
    // Generate report
    const report = await generator.generateReport(testScan, 'html');
    
    // Check report content
    if (report && 
        report.includes(testScan.target) && 
        report.includes('SQL Injection') && 
        report.includes('Cross-Site Scripting')) {
      console.log("✅ Report generation working correctly");
      console.log(`Generated report with ${testScan.vulnerabilities.length} vulnerabilities`);
      return true;
    } else {
      console.log("❌ Report generation failed to include vulnerability details");
      return false;
    }
  } catch (error) {
    console.error("❌ Error testing report generation:", error);
    return false;
  }
}

// Run test
testReportGeneration().then(success => {
  process.exit(success ? 0 : 1);
});
EOF

# Run report generator test
echo "Running report generator test..."
node $TEST_DIR/test_report_generator.js
if [ $? -eq 0 ]; then
  log_test "Report Generator" "PASS" "Generator correctly created reports with vulnerability details"
else
  log_test "Report Generator" "FAIL" "Generator failed to create proper reports"
fi

# Test frontend build
echo "Testing frontend build..."
cd /home/ubuntu/SecurScan/frontend
npm run build
if [ $? -eq 0 ]; then
  log_test "Frontend Build" "PASS" "Frontend built successfully"
else
  log_test "Frontend Build" "FAIL" "Frontend build failed"
fi

# Kill the server process
kill $SERVER_PID

# Summarize test results
echo "====================================="
echo "Test Summary:"
passed=$(grep -c "PASS" $TEST_DIR/test_results.log)
failed=$(grep -c "FAIL" $TEST_DIR/test_results.log)
total=$((passed + failed))

echo "Total tests: $total"
echo "Passed: $passed"
echo "Failed: $failed"

if [ $failed -eq 0 ]; then
  echo "✅ All tests passed!"
  exit 0
else
  echo "❌ Some tests failed. Check $TEST_DIR/test_results.log for details."
  exit 1
fi

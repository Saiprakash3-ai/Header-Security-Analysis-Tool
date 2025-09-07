# Header-Security-Analysis-Tool


Key Features of the Header Security Analyzer:

    Comprehensive Security Header Checks

    HSTS (Strict-Transport-Security): Ensures HTTPS enforcement

    X-Content-Type-Options: Prevents MIME type sniffing

    X-Frame-Options: Protects against clickjacking

    Content-Security-Policy: Prevents XSS attacks

    Referrer-Policy: Controls referrer information leakage

    Cookie Security: Checks HttpOnly, Secure, and SameSite flags

    SSL/TLS Analysis

    Certificate validity and expiration

    Protocol version detection (TLS 1.2+, SSLv3, etc.)

    Weak cipher detection

    Redirect Analysis

    HTTP to HTTPS redirect detection

    Redirect chain analysis

    Security implications of redirects

    Detailed Reporting

    Security scoring system (0-100)

    Severity-based issue categorization

    Specific recommendations for each finding

    Raw headers display

    User-Friendly Interface

    Clean GUI with tabbed interface

    Real-time analysis progress

    Color-coded results (Green/Orange/Red)

    Export functionality

How to Use:

Enter a URL in the input field (e.g., https://example.com)

Click "Analyze Security" to start the analysis

Review the results in the Detailed Results tab:

    Security score and summary

    Individual header analysis

    Specific security issues

    Raw HTTP headers

Export the report for documentation

Security Headers Checked:

 1. Header Purpose Recommended Value

 2. Strict-Transport-Security HTTPS enforcement max-age=31536000; includeSubDomains

 3. X-Content-Type-Options MIME type protection nosniff

 4. X-Frame-Options Clickjacking protection DENY or SAMEORIGIN

 5. Content-Security-Policy XSS protection default-src 'self'

 6. X-XSS-Protection XSS filter 1; mode=block

 7. Referrer-Policy Referrer control strict-origin-when-cross-origin

 8. Permissions-Policy Feature control geolocation=(), microphone=()

 9. Cookie Flags Session security HttpOnly; Secure; SameSite=Strict







Requirements:
bash
pip install requests pyopenssl python-whois dnspython



This tool provides enterprise-level HTTP header security analysis and is essential for web application security assessments, penetration testing, and compliance checking.

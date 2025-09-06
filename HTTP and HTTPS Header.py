import requests
import ssl
import socket
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from urllib.parse import urlparse
import json
from datetime import datetime
import whois
import dns.resolver

class HeaderSecurityAnalyzer:
    def __init__(self):
        self.results = {}
        self.security_headers = {
            'Strict-Transport-Security': {
                'required': True,
                'recommended_value': 'max-age=31536000; includeSubDomains',
                'description': 'Enforces HTTPS connections and prevents SSL stripping attacks'
            },
            'X-Content-Type-Options': {
                'required': True,
                'recommended_value': 'nosniff',
                'description': 'Prevents MIME type sniffing and content type confusion attacks'
            },
            'X-Frame-Options': {
                'required': True,
                'recommended_value': 'DENY',
                'description': 'Protects against clickjacking attacks'
            },
            'X-XSS-Protection': {
                'required': False,
                'recommended_value': '1; mode=block',
                'description': 'Enables XSS protection in older browsers'
            },
            'Content-Security-Policy': {
                'required': True,
                'recommended_value': "default-src 'self'",
                'description': 'Prevents XSS, clickjacking, and other code injection attacks'
            },
            'Referrer-Policy': {
                'required': False,
                'recommended_value': 'strict-origin-when-cross-origin',
                'description': 'Controls how much referrer information is sent with requests'
            },
            'Permissions-Policy': {
                'required': False,
                'recommended_value': 'geolocation=(), microphone=(), camera=()',
                'description': 'Controls which browser features and APIs can be used'
            },
            'Cache-Control': {
                'required': False,
                'recommended_value': 'no-store, no-cache, must-revalidate',
                'description': 'Controls caching behavior to protect sensitive data'
            },
            'Set-Cookie': {
                'required': True,
                'check_attributes': True,
                'description': 'Cookie security attributes (HttpOnly, Secure, SameSite)'
            }
        }

    def analyze_headers(self, url, headers, cookies=None):
        """Analyze HTTP headers for security issues"""
        analysis = {
            'missing_headers': [],
            'insecure_headers': [],
            'secure_headers': [],
            'score': 100,
            'issues': []
        }

        # Check each security header
        for header, config in self.security_headers.items():
            header_value = headers.get(header, '')

            if config['required'] and not header_value:
                analysis['missing_headers'].append(header)
                analysis['score'] -= 10
                analysis['issues'].append({
                    'severity': 'High',
                    'message': f'Missing required security header: {header}',
                    'description': config['description'],
                    'recommendation': f'Add header: {header}: {config["recommended_value"]}'
                })
            elif header_value:
                # Special handling for specific headers
                if header == 'Set-Cookie' and cookies:
                    cookie_issues = self._analyze_cookies(cookies)
                    analysis['issues'].extend(cookie_issues)
                    analysis['score'] -= len(cookie_issues) * 5
                else:
                    is_secure = self._check_header_value(header, header_value, config)
                    if is_secure:
                        analysis['secure_headers'].append(header)
                    else:
                        analysis['insecure_headers'].append(header)
                        analysis['score'] -= 5
                        analysis['issues'].append({
                            'severity': 'Medium',
                            'message': f'Insecure configuration for header: {header}',
                            'description': f'Current: {header_value}. Expected: {config.get("recommended_value", "Secure configuration")}',
                            'recommendation': f'Update to: {config["recommended_value"]}'
                        })

        # Ensure score doesn't go below 0
        analysis['score'] = max(0, analysis['score'])
        
        return analysis

    def _check_header_value(self, header, value, config):
        """Check if header value is secure"""
        value = value.lower()
        
        if header == 'Strict-Transport-Security':
            return 'max-age=' in value and int(value.split('max-age=')[1].split(';')[0]) >= 31536000
        
        elif header == 'X-Content-Type-Options':
            return value == 'nosniff'
        
        elif header == 'X-Frame-Options':
            return value in ['deny', 'sameorigin']
        
        elif header == 'X-XSS-Protection':
            return '1; mode=block' in value
        
        elif header == 'Content-Security-Policy':
            return len(value) > 0  # Basic check - any CSP is better than none
        
        return True

    def _analyze_cookies(self, cookies):
        """Analyze cookie security attributes"""
        issues = []
        for cookie in cookies:
            cookie_issues = []
            
            # Check for HttpOnly flag
            if not getattr(cookie, 'httponly', False):
                cookie_issues.append('Missing HttpOnly flag')
            
            # Check for Secure flag (only if using HTTPS)
            if not getattr(cookie, 'secure', False):
                cookie_issues.append('Missing Secure flag')
            
            # Check for SameSite attribute
            samesite = getattr(cookie, 'samesite', '').lower()
            if samesite not in ['strict', 'lax']:
                cookie_issues.append('Insecure SameSite configuration')
            
            if cookie_issues:
                issues.append({
                    'severity': 'Medium',
                    'message': f'Cookie security issues: {cookie.name}',
                    'description': ', '.join(cookie_issues),
                    'recommendation': 'Set HttpOnly, Secure, and SameSite=Strict flags'
                })
        
        return issues

    def check_ssl_certificate(self, domain):
        """Check SSL certificate validity and configuration"""
        ssl_info = {
            'valid': False,
            'days_until_expiry': 0,
            'issues': [],
            'protocols': [],
            'ciphers': []
        }

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info['valid'] = True
                    
                    # Check certificate expiry
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    ssl_info['days_until_expiry'] = days_until_expiry
                    
                    if days_until_expiry < 30:
                        ssl_info['issues'].append({
                            'severity': 'High',
                            'message': 'SSL certificate expires soon',
                            'description': f'Certificate expires in {days_until_expiry} days',
                            'recommendation': 'Renew SSL certificate immediately'
                        })
                    
                    # Get SSL/TLS protocol information
                    ssl_info['protocol'] = ssock.version()
                    
                    # Check for weak protocols
                    if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        ssl_info['issues'].append({
                            'severity': 'High',
                            'message': 'Weak SSL/TLS protocol detected',
                            'description': f'Using {ssock.version()} which is insecure',
                            'recommendation': 'Disable weak protocols and use TLSv1.2 or higher'
                        })
        
        except Exception as e:
            ssl_info['issues'].append({
                'severity': 'High',
                'message': 'SSL certificate error',
                'description': str(e),
                'recommendation': 'Fix SSL certificate configuration'
            })
        
        return ssl_info

    def get_http_response(self, url):
        """Get HTTP response with headers"""
        try:
            # Try HTTPS first
            if not url.startswith('http'):
                url = 'https://' + url
            
            response = requests.get(
                url, 
                timeout=10,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                },
                allow_redirects=True
            )
            
            return response
        
        except requests.exceptions.SSLError:
            # Fall back to HTTP if HTTPS fails
            if url.startswith('https://'):
                http_url = url.replace('https://', 'http://')
                try:
                    response = requests.get(
                        http_url, 
                        timeout=10,
                        headers={
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        },
                        allow_redirects=True
                    )
                    return response
                except:
                    pass
        
        except:
            pass
        
        return None

    def full_analysis(self, url):
        """Perform complete security analysis"""
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'headers_analysis': {},
            'ssl_analysis': {},
            'redirect_analysis': {},
            'overall_score': 0,
            'recommendations': []
        }

        # Get domain from URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Get HTTP response
        response = self.get_http_response(url)
        
        if not response:
            results['error'] = 'Failed to connect to the URL'
            return results

        # Analyze headers
        results['headers_analysis'] = self.analyze_headers(url, response.headers, response.cookies)
        
        # Analyze SSL if using HTTPS
        if response.url.startswith('https://'):
            results['ssl_analysis'] = self.check_ssl_certificate(domain)
        
        # Analyze redirects
        results['redirect_analysis'] = self.analyze_redirects(response)
        
        # Calculate overall score
        scores = [results['headers_analysis']['score']]
        if results['ssl_analysis'].get('valid', False):
            scores.append(100)  # Full points for valid SSL
        else:
            scores.append(0)
        
        results['overall_score'] = sum(scores) // len(scores)
        
        # Collect all recommendations
        all_issues = (
            results['headers_analysis']['issues'] + 
            results['ssl_analysis'].get('issues', []) +
            results['redirect_analysis'].get('issues', [])
        )
        
        results['recommendations'] = sorted(
            all_issues, 
            key=lambda x: {'High': 3, 'Medium': 2, 'Low': 1}.get(x['severity'], 0),
            reverse=True
        )
        
        return results

    def analyze_redirects(self, response):
        """Analyze HTTP redirect behavior"""
        analysis = {
            'final_url': response.url,
            'redirect_chain': [],
            'issues': []
        }

        # Check if redirected from HTTP to HTTPS
        if response.history:
            for resp in response.history:
                analysis['redirect_chain'].append({
                    'url': resp.url,
                    'status_code': resp.status_code,
                    'headers': dict(resp.headers)
                })
            
            # Check for HTTP to HTTPS redirect
            if response.history[0].url.startswith('http://') and response.url.startswith('https://'):
                analysis['issues'].append({
                    'severity': 'Medium',
                    'message': 'HTTP to HTTPS redirect detected',
                    'description': 'Website redirects from insecure HTTP to secure HTTPS',
                    'recommendation': 'Consider implementing HSTS to enforce HTTPS'
                })
            else:
                analysis['issues'].append({
                    'severity': 'Low',
                    'message': 'Redirect chain detected',
                    'description': f'Redirected through {len(response.history)} URLs',
                    'recommendation': 'Minimize redirects for better performance and security'
                })
        
        return analysis


class HeaderSecurityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HTTP Header Security Analyzer")
        self.root.geometry("1200x800")
        
        self.analyzer = HeaderSecurityAnalyzer()
        
        # Create main notebook
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Analysis tab
        self.analysis_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.analysis_tab, text="Security Analysis")
        
        # Results tab
        self.results_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text="Detailed Results")
        
        self.setup_analysis_tab()
        self.setup_results_tab()
        
    def setup_analysis_tab(self):
        """Setup the analysis tab UI"""
        # Input section
        input_frame = ttk.LabelFrame(self.analysis_tab, text="Website Analysis", padding="10")
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Website URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(input_frame, width=60)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.url_entry.insert(0, "https://")
        
        # Buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        self.analyze_btn = ttk.Button(button_frame, text="Analyze Security", command=self.start_analysis)
        self.analyze_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(button_frame, text="Export Report", command=self.export_report, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        # Results display
        results_frame = ttk.LabelFrame(self.analysis_tab, text="Security Summary", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Score display
        score_frame = ttk.Frame(results_frame)
        score_frame.pack(fill=tk.X, pady=5)
        
        self.score_var = tk.StringVar()
        self.score_var.set("Security Score: N/A")
        score_label = ttk.Label(score_frame, textvariable=self.score_var, font=('Arial', 14, 'bold'))
        score_label.pack()
        
        # Security headers summary
        headers_frame = ttk.LabelFrame(results_frame, text="Security Headers", padding="5")
        headers_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Treeview for headers
        columns = ('header', 'status', 'value', 'recommendation')
        self.headers_tree = ttk.Treeview(headers_frame, columns=columns, show='headings', height=12)
        
        self.headers_tree.heading('header', text='Header')
        self.headers_tree.heading('status', text='Status')
        self.headers_tree.heading('value', text='Value')
        self.headers_tree.heading('recommendation', text='Recommendation')
        
        self.headers_tree.column('header', width=200)
        self.headers_tree.column('status', width=100)
        self.headers_tree.column('value', width=250)
        self.headers_tree.column('recommendation', width=350)
        
        self.headers_tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(headers_frame, orient=tk.VERTICAL, command=self.headers_tree.yview)
        self.headers_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def setup_results_tab(self):
        """Setup the results tab UI"""
        # Issues treeview
        issues_frame = ttk.LabelFrame(self.results_tab, text="Security Issues & Recommendations", padding="10")
        issues_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ('severity', 'message', 'description', 'recommendation')
        self.issues_tree = ttk.Treeview(issues_frame, columns=columns, show='headings', height=15)
        
        self.issues_tree.heading('severity', text='Severity')
        self.issues_tree.heading('message', text='Issue')
        self.issues_tree.heading('description', text='Description')
        self.issues_tree.heading('recommendation', text='Recommendation')
        
        self.issues_tree.column('severity', width=80)
        self.issues_tree.column('message', width=200)
        self.issues_tree.column('description', width=300)
        self.issues_tree.column('recommendation', width=300)
        
        self.issues_tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(issues_frame, orient=tk.VERTICAL, command=self.issues_tree.yview)
        self.issues_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Raw headers display
        raw_frame = ttk.LabelFrame(self.results_tab, text="Raw HTTP Headers", padding="10")
        raw_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.raw_text = scrolledtext.ScrolledText(raw_frame, width=80, height=10)
        self.raw_text.pack(fill=tk.BOTH, expand=True)
        
    def start_analysis(self):
        """Start security analysis"""
        url = self.url_entry.get().strip()
        if not url or url == "https://":
            messagebox.showerror("Error", "Please enter a valid URL")
            return
        
        # Clear previous results
        for item in self.headers_tree.get_children():
            self.headers_tree.delete(item)
        for item in self.issues_tree.get_children():
            self.issues_tree.delete(item)
        self.raw_text.delete(1.0, tk.END)
        
        # Update UI
        self.analyze_btn.config(state=tk.DISABLED)
        self.score_var.set("Analyzing...")
        
        # Run analysis in separate thread
        def analysis_thread():
            try:
                results = self.analyzer.full_analysis(url)
                
                # Update UI with results
                self.root.after(0, self.display_results, results)
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Analysis failed: {str(e)}"))
                self.root.after(0, lambda: self.analyze_btn.config(state=tk.NORMAL))
        
        threading.Thread(target=analysis_thread, daemon=True).start()
    
    def display_results(self, results):
        """Display analysis results"""
        # Update score
        score = results.get('overall_score', 0)
        color = 'green' if score >= 80 else 'orange' if score >= 60 else 'red'
        self.score_var.set(f"Security Score: {score}/100")
        
        # Display headers
        headers_analysis = results.get('headers_analysis', {})
        response = self.analyzer.get_http_response(results['url'])
        
        if response:
            for header, value in response.headers.items():
                status = "✅ Secure" if header in headers_analysis.get('secure_headers', []) else "⚠️ Insecure" if header in headers_analysis.get('insecure_headers', []) else "ℹ️ Present"
                self.headers_tree.insert('', tk.END, values=(header, status, str(value), ""))
            
            # Add missing headers
            for header in headers_analysis.get('missing_headers', []):
                config = self.analyzer.security_headers.get(header, {})
                self.headers_tree.insert('', tk.END, values=(
                    header, 
                    "❌ Missing", 
                    "Not present", 
                    config.get('recommendation', 'Add this security header')
                ))
            
            # Display raw headers
            self.raw_text.insert(tk.END, f"HTTP/{response.raw.version} {response.status_code} {response.reason}\n")
            for header, value in response.headers.items():
                self.raw_text.insert(tk.END, f"{header}: {value}\n")
        
        # Display issues
        for issue in results.get('recommendations', []):
            self.issues_tree.insert('', tk.END, values=(
                issue['severity'],
                issue['message'],
                issue['description'],
                issue['recommendation']
            ))
        
        # Enable export button
        self.export_btn.config(state=tk.NORMAL)
        self.analyze_btn.config(state=tk.NORMAL)
        
        # Switch to results tab
        self.notebook.select(1)
    
    def export_report(self):
        """Export analysis report to JSON file"""
        try:
            # For simplicity, we'll just show a message
            messagebox.showinfo("Export", "Report export functionality would save results to a JSON file")
            # In a real implementation, you'd save the results to a file
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report: {str(e)}")


# Run the application
if __name__ == "__main__":
    import threading
    
    root = tk.Tk()
    app = HeaderSecurityGUI(root)
    root.mainloop()

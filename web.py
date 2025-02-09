from flask import Blueprint, render_template, request
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin

# Define the Web Blueprint
web = Blueprint('web', __name__, template_folder='templates')

# Preprocessing function to clean and extract text from URLs
def preprocess_text(text):
    text = text.lower()
    text = re.sub(r'[^a-zA-Z0-9./:\s]', '', text)
    return text

# Extract URLs from a web page
def get_urls_from_page(base_url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(base_url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        return [urljoin(base_url, link['href']) for link in links]
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {base_url}: {e}")
        return []

# Risk levels and solutions for vulnerabilities
def get_vulnerability_details(vulnerability):
    details = {
        "SQL Injection Detected": {
            "risk_level": "High",
            "description": "Occurs when user inputs are directly included in SQL queries without validation or sanitization.",
            "solution": "Use parameterized queries or prepared statements to prevent SQL Injection."
        },
        "Potential XSS Vulnerability": {
            "risk_level": "Medium",
            "description": "Occurs when untrusted user input is rendered in the browser without proper sanitization.",
            "solution": "Validate and sanitize user input, and use Content Security Policy (CSP)."
        },
        "Path Traversal Detected": {
            "risk_level": "Low",
            "description": "Occurs when attackers manipulate file paths to access restricted files.",
            "solution": "Validate and sanitize file path inputs, and use access control mechanisms."
        },
        "Potential CSRF Vulnerability": {
            "risk_level": "Low",
            "description": "Occurs when a malicious website tricks a user into performing unwanted actions.",
            "solution": "Implement CSRF tokens in forms and validate them on the server side."
        },
        "Potential Command Injection Vulnerability": {
            "risk_level": "High",
            "description": "Occurs when untrusted input is executed as a command on the server.",
            "solution": "Validate and sanitize all inputs, and use libraries that prevent command execution."
        },
        "Open Redirect Detected": {
            "risk_level": "Medium",
            "description": "Occurs when attackers redirect users to malicious websites.",
            "solution": "Validate and whitelist allowed redirect URLs."
        }
    }
    return details.get(vulnerability, {"risk_level": "Unknown", "description": "Unknown", "solution": "Unknown"})

# Function to check for vulnerabilities
def check_for_vulnerabilities(response_text, url):
    vulnerabilities = []
    if re.search(r"syntax error|mysql|sql", response_text, re.IGNORECASE):
        vulnerabilities.append("SQL Injection Detected")
    if re.search(r"<script.*?>.*?</script>", response_text, re.IGNORECASE):
        vulnerabilities.append("Potential XSS Vulnerability")
    if re.search(r"\.\./|\.\.\/|/etc/passwd", url, re.IGNORECASE):
        vulnerabilities.append("Path Traversal Detected")
    if "<form" in response_text.lower() and "csrf" not in response_text.lower():
        vulnerabilities.append("Potential CSRF Vulnerability")
    if re.search(r"\b(sh|bash|cmd|powershell)\b", response_text, re.IGNORECASE):
        vulnerabilities.append("Potential Command Injection Vulnerability")
    if "location" in response_text.lower() and "redirect" in response_text.lower():
        vulnerabilities.append("Open Redirect Detected")
    return vulnerabilities

# Function to analyze each URL
def analyze_url(url):
    try:
        response = requests.get(url)
        vulnerabilities = check_for_vulnerabilities(response.text, url)
        details = [
            {"name": v, **get_vulnerability_details(v)} for v in vulnerabilities
        ]
        return {"url": url, "status": response.status_code, "vulnerabilities": details}
    except requests.exceptions.RequestException as e:
        return {"url": url, "status": "Error", "vulnerabilities": [{"name": "Error", "description": str(e), "risk_level": "N/A", "solution": "N/A"}]}

# Route for the homepage (where users input the URL)
@web.route('/')
def index():
    return render_template('web.html')

# Route for scanning the URL
@web.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    urls = get_urls_from_page(url)[:20]  # Limit to 20 URLs for scanning
    results = [analyze_url(link) for link in urls]
    return render_template('webresult.html', results=results, scanned_url=url)

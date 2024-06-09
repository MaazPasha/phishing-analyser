from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse
from flask import Flask, request, render_template
import socket

app = Flask(__name__)

# Define your trusted TLDs
trusted_tlds = {'com', 'in'}  # Add more TLDs as needed

def get_html_content(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        response.raise_for_status()
        return response.text

    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"Error fetching URL: {err}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return None

def analyze_phishing(html_content, url):
    if not html_content:
        return "Error: Unable to fetch HTML content", []

    soup = BeautifulSoup(html_content, 'html.parser')
    detected_indicators = set()

    # Check for common phishing indicators in meta tags
    meta_tags = soup.find_all('meta', {'http-equiv': 'refresh'})
    if meta_tags:
        detected_indicators.add("Page uses automatic redirection")

    # Check for suspicious links
    suspicious_links = soup.find_all('a', href=True)
    for link in suspicious_links:
        href = link['href']
        parsed_url = urlparse(href)
        if parsed_url.scheme and parsed_url.netloc and not is_trusted_domain(parsed_url.netloc):
            detected_indicators.add("Contains suspicious links")
            break  # Stop after finding the first suspicious link

    # Analyze the content for phishing indicators
    phishing_keywords = {'login', 'password', 'account', 'verify'}
    for keyword in phishing_keywords:
        keyword_count = html_content.lower().count(keyword)
        if keyword_count > 1:
            detected_indicators.add(f"Contains multiple instances of phishing keyword: {keyword}")

    # Check for phishing patterns in form actions
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action', '').lower()
        if action and action.startswith('http://'):
            detected_indicators.add("Form action uses HTTP instead of HTTPS")

    # Additional conditions for phishing detection
    if "confirm" in html_content.lower() and "identity" in html_content.lower():
        detected_indicators.add("May be attempting to confirm identity")

    if not detected_indicators:
        detected_indicators.add("No phishing indicators found")

    result = "Legitimate" if len(detected_indicators) == 1 and "No phishing indicators found" in detected_indicators else "Phishing"
    return result, list(detected_indicators)


def is_trusted_domain(domain):
    # List of trusted domain extensions
    trusted_extensions = {".com", ".in", ".org",".html",".php",".support"}

    # Check if the domain ends with any trusted extension
    for extension in trusted_extensions:
        if domain.endswith(extension):
            return True
    
    return False

def is_domain_valid(domain):
    try:
        # Perform a DNS lookup to verify if the domain exists
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

# Example usage in a simple Flask web application
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_phishing():
    url = request.form.get('url')

    # Basic URL validation
    if not url:
        return render_template('error.html', error="Error: URL is required")

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # Check if the entered domain is valid and trusted
    if not is_domain_valid(domain):
        return render_template('error.html', error="Error: Invalid domain")
    elif not is_trusted_domain(domain):
        return render_template('error.html', error="Error: Untrusted domain")

    html_content = get_html_content(url)

    if not html_content:
        return render_template('error.html', error="Error: Unable to fetch HTML content")

    result = analyze_phishing(html_content, url)
    return render_template('result.html', url=url, result=result)

@app.route('/error')
def error():
    error_message = "An unexpected error occurred."
    return render_template('error_page.html', error=error_message)

if __name__ == '__main__':
    # Disable debug mode in production
    app.run(debug=True)
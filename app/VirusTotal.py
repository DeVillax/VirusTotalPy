#!/usr/bin/env python
# Simple API for VirusTotal v2

__author__ = "NcVillalobos"
__copyright__ = "Copyright 2019, NcVillalobos"
__credits__ = ["NcVillalobos"]
__version__ = 0.2
__status__ = "Development"


import requests


class VirusTotal(object):

    def __init__(self, api):
        self.api = api
        self.base = "https://www.virustotal.com/vtapi/v2/"

    @property
    def api(self):
        return self.__api

    @api.setter
    def api(self, api):
        self.__api = api

# --------------------Files Methods ----------------------------------------

    def file_scan(self, file):
        # Scan a file no bigger than 32 MB
        url = f"{self.base}file/scan"
        params = {"apikey": self.api}
        data = {"file": (file, open(file, "rb"))}
        response = requests.post(url, files=data, params=params)
        return response.json()

    def file_rescan(self, resource):
        # Re-scan a file
        # Resource can be the MD5,SHA-1 or SHA-256 of the file
        url = f"{self.base}file/rescan"
        params = {"apikey": self.api, "resource": resource}
        response = requests.post(url, params=params)
        return response.json()

    def file_download(self, resource):
        # Download a file
        # Resource can be the MD5,SHA-1 or SHA-256 of the file
        # Private API
        url = f"{self.base}file/download"
        params = {"apikey": self.api, "hash": resource}
        response = requests.get(url, params=params)
        if response.status_code == 200:
            return response.content
        elif response.status_code == 403:
            return "Your API doesn't have the right privileges to use this method."

    def file_behaviour(self, resource):
        # Retrieve behaviour report
        # Resource can be the MD5,SHA-1 or SHA-256 of the file
        # Private API
        url = f"{self.base}file/behaviour"
        params = {"apikey": self.api, "hash": resource}
        response = requests.get(url, params=params)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            return "Your API doesn't have the right privileges to use this method."

    def file_networktraffic(self, resource):
        # Retrieve network traffic report
        # Resource can be the MD5,SHA-1 or SHA-256 of the file
        # Private API
        url = f"{self.base}file/network-traffic"
        params = {"apikey": self.api, "hash": resource}
        response = requests.get(url, params=params)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            return "Your API doesn't have the right privileges to use this method."

    def file_feed(self, time_window):
        # Retrieve live feed of all files submitted to VirusTotal
        # Private API
        url = f"{self.base}file/feed"
        params = {"apikey": self.api, "package": time_window}
        response = requests.get(url, params=params, stream=True, allow_redirects=True)
        if response.status_code == 200:
            return response.content
        elif response.status_code == 403:
            return "Your API doesn't have the right privileges to use this method."

    def file_clusters(self, date):
        # Retrieve file clusters
        # Private API
        url = f"{self.base}file/clusters"
        params = {"apikey": self.api, "date": date}
        response = requests.get(url, params=params)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            return "Your API doesn't have the right privileges to use this method."

    def file_search(self, query, offset=""):
        # Search for files
        # Private API
        url = f"{self.base}file/search"
        params = {"apikey": self.api, "query": query, "offset": offset}
        response = requests.get(url, params=params)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            return "Your API doesn't have the right privileges to use this method."

    def file_report(self, resource, allinfo=False):
        # Retrieve File Report
        # Resource variable can be the MD5,SHA-1, SHA-256 or the scan id
        # The allinfo variable is an optional parameter available for Private API only.
        # If it is set to true, it will display additional information other than the AV results.
        url = f"{self.base}file/report"
        params = {"apikey": self.api, "resource": resource, "allinfo": allinfo}
        response = requests.get(url, params=params)
        return response.json()

# --------------------URL Methods---------------------------------------------

    def scan_url(self, url):
        # Submit an url to be scanned
        url_vt = f"{self.base}url/scan"
        params = {"apikey": self.api, "url": url}
        response = requests.post(url_vt, params=params)
        return response.json()

    def url_report(self, url):
        # Retrieve URL Report
        url_vt = f"{self.base}url/report"
        params = {"apikey": self.api, "resource": url}
        response = requests.get(url_vt, params=params)
        return response.json()

    def url_feed(self, time_window):
        # Retrieve live feed of all URLs submitted to VirusTotal
        # Requires Private API
        url = f"{self.base}url/feed"
        params = {"apikey": self.api, "package": time_window}
        response = requests.request("GET", url, params=params)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            return "Your API doesn't have the right privileges to use this method."

# ---------------------------Domain & IP methods ------------------------------------------------
    def ip_report(self, ip):
        # Retrieve IP Report
        url = f"{self.base}ip-address/report"
        params = {"apikey": self.api, "ip": ip}
        response = requests.get(url, params=params)
        return response.json()

    def domain_report(self, domain):
        # Retrieve domain report
        url = f"{self.base}domain/report"
        params = {"apikey": self.api, "domain": domain}
        response = requests.get(url, params=params)
        return response.json()

# ---------------------------Comments methods---------------------

    def get_comments(self, resource):
        # Get comments for a file or URL
        # Private API
        url = f"{self.base}comments/get"
        params = {"apikey": self.api, "resource": resource}
        response = requests.request("GET", url, params=params)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            return "Your API doesn't have the right privileges to use this method."

    def put_comment(self, resource, comment):
        # Post comment for a file or URL
        url = f"{self.base}comments/put"
        params = {"apikey": self.api, "resource": resource, "comment": comment}
        response = requests.post(url, params=params)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            return "Your API doesn't have the right privileges to use this method."

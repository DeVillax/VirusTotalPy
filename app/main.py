#!/usr/bin/env python

__author__ = "NcVillalobos"
__copyright__ = "Copyright 2019, NcVillalobos"
__credits__ = ["NcVillalobos"]
__license__ = "MIT"
__version__ = 0.3
__status__ = "Development"



from VirusTotal import retrieve_file_report, submit_file, retrieve_ip_report, retrieve_url_report
from hashes import *
from MetaDefenderCloud import retrieve_hash_information, retrieve_ip_information, retrieve_url_information
from tkinter.filedialog import askopenfilename
from Exceptions import FieldNotAvailable

import re
import sys
import time
import json

# ----------------------------------------------------------------------------------------------
# Hash Methods


def generate_hashes():
    # Returns a dictionary with the md5, sha1 and sha256 hashes
    file = askopenfilename()
    hashes = {"md5": 0, "sha1": 0, "sha256": 0}

    hashes["md5"] = obtain_md5(file)
    hashes["sha1"] = obtain_sha1(file)
    hashes["sha256"] = obtain_sha256(file)

    return hashes


def print_hashes(hashes):
    # Print the hashes given

    # file_search = re.search(r"\w+[.]\w+$", file)
    # filename = file_search.group()
    print(f"The MD5 hash for is {hashes['md5']}")
    print(f"The Sha1 hash for is {hashes['sha1']}")
    print(f"The Sha256 hash for is {hashes['sha256']}")
    print()


def select_hash(hashes):
    # Selects which hash the user would like to check
    print("The following hashes can be checked:")
    print("1) MD5")
    print("2) SHA1")
    print("3) SHA256")
    try:
        selection = int(input("Please select one: "))
        if selection < 1 or selection > 3:
            raise ValueError
    except ValueError:
        print("There is no hash associate to the option entered. Please select other.")
    else:
        if selection == 1:
            check_hash(hashes["md5"])
        elif selection == 2:
            check_hash(hashes["sha1"])
        else:
            check_hash(hashes["sha256"])


def check_hash(hash):
    # Check the given hash on VirusTotal and Metadefender

    # Responses
    response_virustotal= retrieve_file_report(hash)
    response_metadefender = retrieve_hash_information(hash)

    # VirusTotal results
    if response_virustotal["response_code"] == 0:
        print("There is no report associated to this hash on VirusTotal.")
    else:
        total_detected_virustotal = response_virustotal["positives"]
        total_avs_virustotal = response_virustotal["total"]
        print(f"Virustotal detection ratio: {total_detected_virustotal}/{total_avs_virustotal}")
        if total_detected_virustotal != 0:
            print("VirusTotal")
            for AV in response_virustotal["scans"]:
                if response_virustotal["scans"][AV]["detected"] == True:
                    print(f"{AV} -- {response_virustotal['scans'][AV]['result']}")

    # Metadefender results
    if response_metadefender["error"]["code"] == 404003:
        print("There is no report associated to this hash on MetaDefender.")
    else:
        total_detected_metadefender = response_metadefender["scan_results"]["total_detected_avs"]
        total_avs_metadefender = response_metadefender["scan_results"]["total_avs"]
        print(f"Metadefender detection ratio: {total_detected_metadefender}/{total_avs_metadefender}\n")
        if total_detected_metadefender != 0:
            print("\nMetadefender")
            for AV in response_metadefender["scan_results"]["scan_details"]:
                if response_metadefender['scan_results']['scan_details'][AV]['threat_found'] != "":
                    print(f"{AV} -- {response_metadefender['scan_results']['scan_details'][AV]['threat_found']}")

# ----------------------------------------------------------------------------------------------
# IP Address Methods

def check_ip_virustotal(ip):

    # Response
    response_virustotal = retrieve_ip_report(ip)

    print(f"Results for {ip}:")

    if "continent" in response_virustotal:
        print(f"Continent: {response_virustotal['continent']}")

    if "country" in response_virustotal:
        print(f"Country: {response_virustotal['country']}")

    if "as_owner" in response_virustotal:
        print(f"Owner: {response_virustotal['as_owner']}")

    if "network" in response_virustotal:
        print(f"Network: {response_virustotal['network']}")
    print("Hostname/s associated:")

    for resolution in response_virustotal["resolutions"]:
        print(f"\thostname: {resolution['hostname']}")

    if "detected_urls" in response_virustotal:
        if len(response_virustotal["detected_urls"]) > 0:
            print("Detected URLs:")
            for detected_url in response_virustotal["detected_urls"]:
                print(f"URL: {detected_url['url']}")
                print(f"Detection ratio: {detected_url['positives']}/{detected_url['total']}")
                print()

    if "detected_downloaded_samples" in response_virustotal:
        print("Detected Downloaded Samples:")
        for sample in response_virustotal["detected_downloaded_samples"]:
            print(f"SHA: {sample['sha256']}")
            print(f"Detection ratio: {sample['positives']}/{sample['total']}")
            print()


def check_ip_metadefender(ip):
    response = retrieve_ip_information(ip)

    print(f"Results for {ip}:")
    if "continent" in response:
        print(f"Continent: {response['geo_info']['continent']['name']}")

    if "country" in response:
        print(f"Country: {response['geo_info']['country']['name']}")
    print(f"Detected by {response['lookup_results']['detected_by']} AV/s")

#-----------------------------------------------------------------------------------------------------------------------
# URL Methods


def check_url_virustotal(url):
    response = retrieve_url_report(url)

    print(f"Results for {url}:")
    print(f"Latest scan was made on {response['scan_date']}")
    print(f"This url was detected by {response['positives']}/{response['total']}")

    if response["positives"] != 0:
        for scan in response["scans"]:
            if scan["detected"]:
                print(scan)


def check_url_metadefender(url):
    response = retrieve_url_information(url)
    print(json.dumps(response, indent=4))

    print(f"Results for {url}:")
    print(f"This url was detected by {response['positives']} AV/s")

    if response["detected_by"] != 0:
        for scan in response["lookup_results"]["sources"]:
            if scan["detected_time"] != "":
                print(scan["provider"])


if __name__ == '__main__':
    check_url_metadefender("")

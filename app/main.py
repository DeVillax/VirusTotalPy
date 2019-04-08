from VirusTotal import retrieve_file_report, submit_file, retrieve_ip_report
from hashes import *
from MetaDefenderCloud import retrieve_hash_information
from tkinter.filedialog import askopenfilename
import re
import sys
import time
import json


def welcome_message():
    print("*"*30)
    print("Welcome to the Hash Checker App")
    print("*"*30)
    print("What would you like to do today?")
    print("1) Check hash")
    print("2) Check IP Address")
    print("3) Exit")


def final_operation():
    while 1:
        option = input("Would you like to perform any other operation? (Y/N)")
        if option.upper() != "Y" and option.upper() != "N":
            print("The option entered is not valid. Please try again")
        else:
            if option.upper() == "Y":
                welcome_message()
                break
            else:
                print("Closing the program...")
                sys.exit()


def menu():
    welcome_message()
    while 1:
        try:
            option = int(input("Select Option:"))
        except ValueError:
            print("The option entered doesn't exist. Please try again.")
        else:
            if option == 1:
                hashes = generate_hashes()
                print_hashes(hashes)
                select_hash(hashes)
                final_operation()
            elif option == 2:
                # TO be Completed
                final_operation()
            elif option == 3:
                print("Closing the program...")
                sys.exit()
            else:
                print("The option entered doesn't exist. Please try again")


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


if __name__ == '__main__':
    menu()

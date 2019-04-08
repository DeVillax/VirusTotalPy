import requests
API_KEY = ""


def submit_file(file):
    # Not completed
    metadefender_url = f"https://api.metadefender.com/v4/file"
    headers = {"apikey": API_KEY, "filename": file, "content-type": "", "Body": ""}
    response = requests.post(metadefender_url, headers=headers)
    return response.json()


def retrieve_hash_information(hash):
    metadefender_url = f"https://api.metadefender.com/v4/hash/{hash}"
    headers = {"apikey": API_KEY}
    response = requests.get(metadefender_url, headers=headers)
    return response.json()

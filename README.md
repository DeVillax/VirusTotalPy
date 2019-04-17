# Signature-checker
Program to perform a set of actions on VirusTotal and Metadefender Cloud. This set comprises the following actions:

* Hash

Compute the md5, sha1 and sha256 of a file and check whether there is a record associate on VirusTotal and MetaDefender

* Files

Upload files to Virustotal and MetaDefender and display the results

* IP addresses

Check whether any AVs detects issues with a given IP address

* URL

Check whether any Avs detecs issues with a given URL


## Checklist
### Hash
- [x] Generate
  - [x] MD5
  - [x] SHA1
  - [x] SHA256
- [x] Check the hashes on VirusTotal and MetaDefender
- [x] Display information found, if any

### Files
- [ ] Upload files to Virustotal and MetaDefender
- [ ] Display information

### IP Addresses
- [x] Check IP addresses on VirusTotal and MetaDefender
  - [x] Check a given IP address on VirusTotal
  - [x] Check a given IP address on MetaDefender
- [ ] Validate given IP address
- [x] Display information
  - [x] Display information fetched from VirusTotal
  - [x] Display information fetched from MetaDefenderCloud

### URL 
- [x] Check url on VirusTotal and MetaDefender
  - [x] Check a given URL on VirusTotal
  - [x] Check a given URL on MetaDefender
- [x] Display information
  - [x] Display information fetched from VirusTotal
  - [x] Display information fetched from MetaDefenderCloud

### GUI
- [ ] Create a GUI
  

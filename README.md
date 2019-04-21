# VirusTotalPy
## Description
VirusTotalPy is a simple client wrapper for the VirusTotal Web API.

## Dependencies
* Requests - spotipy requires the requests package to be installed

## Quick Start
Simply import virustotalpy to your project, create a VirusTotalPy object and call its methods:

    import virustotalpy
    vt = virustotalpy.VirusTotalPy("<----YOUR API KEY --->")
    
    report = vt.ip_report("<---- IP to be scanned -->")
    print(report)
    
  

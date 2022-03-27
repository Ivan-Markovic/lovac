# Lovac
**POC script for Malware Hunting over the WWW**

To start with Malware Hunting, execute: python3 ./lovac.py.

The script will start looking for random domain names, download first page to ./lovac_download/ folder and parse interesting strings to the ./lovac_output/ folder. After the tool is done, you can analyze output files manually and run the antivirus scan on download folder.
The tool will save current status of discovery process in ./lovac_discovered.txt and ./lovac_tried.txt files.

# Additional options

Discover "co.rs" domains, with minimum length 2 and maximum length 6, try 10k combinations and use only letters "abvgdjezijklm":

**# python3 ./lovac.py --tld "co.rs" --min 2 --max 6 --repeat 10000 --chars "abvgdjezijklm"**

Discover domains from keyword list and append ".rs":

**# python3 ./lovac.py --list LIST_KEYWORDS_OR_DOMAINS.txt --appendtld --tld "rs"**

_For all options run: python3 ./lovac.py -h_

# Requirements

Tool is based on: Python3, Curl and Grep. You should probably have them in the PATH.

# Recommendations

For Antivirus scanning on Linux you can use ClamAV (or any other available).
Be sure that you know what are you doing if you proceed with further investigation, use proper Sandbox via Virtual Machine.
For reversing obsfucated javascript you can use tools like: https://github.com/lelinhtinh/de4js.

# TODO

There is a lot that can be improved, for the start:
* Extract/Spider extracted URLs
* Add more detections/patterns
* Minimize false positives/negatives
* Improve Reporting for less technical folks
* Optimize code
* Add external interfaces/detections

# POC

This script (with help of ClamAV and little bit of HTML source investigation) already detected more then 20 compromised websites in less than of 24 hours of running.

Some examples are:
* IFRAME with malicious link
* Javascript redirection to the Malware
* Javascript hide malicious advertising
* Defaced web site
* Possible Crypto Minner traces
* Private Information Leak
* Misconfigured DNS

_Details can be found via Twitter tags #Bezbednost #Malware_ and in summary presentation: https://github.com/Ivan-Markovic/lovac/blob/main/How_To_Hunt_Malware_and_Others_with_Lovac.pdf 

# Testing

Script is under heavy development and it is not tested in details. Please feel free to report any bugs, upgrades and recommendations.

# Initial idea

Check here: https://twitter.com/ivanmarkovicsec/status/1501640436296949767

_Happy Hunting :)_


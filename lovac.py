#!/usr/bin/python3

# POC script for Malware hunting v0.0.1, contact: ivanm@security-net.biz
# More info here: https://twitter.com/ivanmarkovicsec/status/1501640436296949767
# TODO: 1. Extract/Spider extracted URLs 2. Add more detections/patterns, 3. Minimize false positives/negatives
# TODO: 4. Improve Reporting for less technical folks, 5. Optimize code, 6. Add external interfaces/detections, ...

# Imports
import glob
import random, string, time, subprocess, argparse, os, datetime

# Main Start Time
start_time = time.time()
t_now = datetime.datetime.now()

print("\n: Welcome to the Lovac Malware Hunter interface v0.0.1 :)\n")

# Arguments
parser = argparse.ArgumentParser("Lovac 0.0.1")
parser.add_argument("-t", "--tld", help="Top Level Domain", default="rs")
parser.add_argument("-s", "--sleep", help="Mysterious Sleep function! Tune it... Default: 49", default=49)
parser.add_argument("-a", "--min", help="Minimum domain length. Default: 1", default=1)
parser.add_argument("-b", "--max", help="Maximum domain length. Default: 8", default=8)
parser.add_argument("-r", "--repeat", help="How many random combinations to try? Default: 1000", default=1000)
parser.add_argument("-c", "--chars", help="Set character set (default string.ascii_lowercase)", default="")
parser.add_argument("-l", "--list", help="List of domains to scan.", default='')
parser.add_argument("-x", "--appendtld", help="Append TLD to the list.", action='store_true')
parser.add_argument("-u", "--ua", help="User Agent string",
                    default="Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0; MDDCJS)")
args = parser.parse_args()

# Prepare FS
if not os.path.isfile('./lovac_discovered.txt'):
    f = open("lovac_discovered.txt", "w").close()
if not os.path.isfile('./lovac_tried.txt'):
    f = open("lovac_tried.txt", "w").close()
if not os.path.isdir('./lovac_download'):
    os.mkdir('./lovac_download')
if not os.path.isdir('./lovac_output'):
    os.mkdir('./lovac_output')

# Load old ones
all_domains_discovered = []
with open("lovac_discovered.txt") as file_domains_discovered:
    for line in file_domains_discovered:
        all_domains_discovered.append(line.rstrip())

all_domains_probed = []
with open("lovac_tried.txt") as file_domains_probed:
    for line in file_domains_probed:
        all_domains_probed.append(line.rstrip())

# Setup counters
proces_status_max = 0
count_temp = 0
count_proc = 0
count_duplicate = 0

# Print status
print(": Status")
print("Current: " + str(count_proc))
print("Discovered: " + str(len(all_domains_discovered)))
print("Tried: " + str(len(all_domains_probed)))
print("Duplicate: " + str(count_duplicate))
print()

# Chose character set
if args.chars != "":
    c_set = args.chars
else:
    c_set = string.ascii_lowercase

if args.list == '':  # Random mode
    proces_status_max = int(args.repeat)
else:  # List mode
    all_domains_list = []
    with open(args.list) as file_domains_list:
        for line in file_domains_list:
            if args.appendtld:
                all_domains_list.append(line.rstrip() + "." + args.tld)
            else:
                all_domains_list.append(line.rstrip())
    proces_status_max = int(len(all_domains_list)) - 1

print(": Starting Scan")
while count_proc <= proces_status_max:

    if args.list == '':
        # Get random name
        domain_random = ''.join(
            random.choices(c_set, k=random.randrange(int(args.min), int(args.max) + 1))) + "." + args.tld
    else:
        # Get domain name from the list
        domain_random = all_domains_list[count_proc]

    # Count rounds
    count_proc += 1

    if domain_random not in all_domains_discovered and domain_random not in all_domains_probed:
        count_temp += 1
        print("Guessing: " + domain_random)

        # Execute Curl
        try:
            curl_ret = subprocess.check_output(
                'curl -s --connect-timeout 20 -i -A "' + args.ua + '" ' + '"http://' + domain_random + '"',
                shell=True, stderr=subprocess.STDOUT).decode()
            all_domains_discovered.append(domain_random)
            textfile = open("lovac_download/" + domain_random + ".txt", "w")
            textfile.write(curl_ret)
            textfile.close()
            # Repeat on Location Header
            if "Location:" in curl_ret or "location:" in curl_ret:
                curl_ret = subprocess.check_output(
                    'curl -s -L --connect-timeout 20 -i -A "' + args.ua + '" ' + '"' + domain_random + '"',
                    shell=True, stderr=subprocess.STDOUT).decode()
                textfile = open("lovac_download/" + domain_random + ".txt", "w")
                textfile.write(curl_ret)
                textfile.close()
        except Exception as e:
            all_domains_probed.append(domain_random)

        # Process data, Grep some IOC
        print("Grepping IOC (HTML, Include, Script, Crypto)")
        try:
            # HTML; False Positive: "speCIALISt", ...
            curl_ret = subprocess.check_output(
                'grep -irE "hacked|viagra|cialis|rolex|ralph lauren" ./lovac_download/'+domain_random+'* >> ./lovac_output/'+domain_random+'_output_html.txt',
                shell=True, stderr=subprocess.STDOUT).decode()
        except Exception as e:
            pass

        try:
            # INCLUDE; False Positive: Google, Facebook, ...
            curl_ret = subprocess.check_output(
                'grep -irE "\.co\.yu|\<iframe|script.+\.txt" ./lovac_download/'+domain_random+'* >> ./lovac_output/'+domain_random+'_output_include.txt',
                shell=True, stderr=subprocess.STDOUT).decode()
        except Exception as e:
            pass

        try:
            # CRYPTO; False Positive: TODO
            curl_ret = subprocess.check_output(
                'grep -irE "crypto|bitcoin|bit coin" ./lovac_download/'+domain_random+'* >> ./lovac_output/'+domain_random+'_output_crypto.txt',
                shell=True, stderr=subprocess.STDOUT).decode()
        except Exception as e:
            pass

        try:
            # SCRIPT; False Positive: TODO
            curl_ret = subprocess.check_output(
                'grep -irE "document\[_|var._0x|eval" ./lovac_download/'+domain_random+'* >> ./lovac_output/'+domain_random+'_output_script.txt',
                shell=True, stderr=subprocess.STDOUT).decode()
        except Exception as e:
            pass

        # Random Sleep
        if 7 == random.randrange(0, int(args.sleep)):
            time.sleep(random.randrange(2, 3))
    else:
        count_duplicate += 1
        print("Duplicate: " + domain_random + ".rs")

    # Backup results (on every 50 discovered)
    if count_temp == 50 or count_proc == proces_status_max:
        count_temp = 0
        # Discovered
        textfile = open("lovac_discovered.txt", "w")
        for element in all_domains_discovered:
            textfile.write(element + "\n")
        textfile.close()
        # Probed
        textfile = open("lovac_tried.txt", "w")
        for element in all_domains_probed:
            textfile.write(element + "\n")
        textfile.close()

    # Print status
    if count_proc % 50 == 0:
        print("\n: Status")
        print("Current: " + str(count_proc))
        print("Discovered: " + str(len(all_domains_discovered)))
        print("Tried: " + str(len(all_domains_probed)))
        print("Duplicate: " + str(count_duplicate))
        print("Executed in %s seconds" % (time.time() - start_time))
        print("")

# Clenup empty
for t_file in glob.glob("./lovac_output/*.*"):
    try:
        if os.path.getsize(t_file) == 0:
            os.remove(t_file)
    except Exception as e:
        pass

print("\nAll done. Check/Inspect/Reverse ./lovac_output/ files and scan ./lovac_download/ folder with Anti Virus software.")
print("\n\n... if you think you are too small to make a difference, try sleeping with a mosquito ...\n\n")

#!/usr/bin/env bash

# A simple bash script for automating network enumeration

# It's not very good and will hopefully be updated to Python with
# multithreading/processing support

# Arguments designed based on standard/compatability with planned Python upgrade

# Missing DNSUnum, SNMPWalk, Enum4linux, ... 
# Will hopefully add once approved...


# Complain about incorrect parameters
if [ "$#" -le 4 -o "$#" -ge 7 ]; then
    echo "usage: ./enum.sh <target_file> [-p <ports>] [-i <interface>]"\
    "[--nmap | --nmap-full]"
    echo ""
    echo "Order of arguments matters!!"
    echo "------------------------------------------------------------"
    echo "  -p:               ports to zmap for < MUST BE \",\" DELIMIATED!"
    echo "                    -a for top 100 ports"
    echo "  -i:               interface to use during zmap scan"
    echo "  --nmap:           perform nmap scan of zmap results"
    echo "  --nmap-full:      perform nmap scan of full target range"
    echo ""
    echo "EXAMPLES"
    echo "  ./enum.sh targets.csv -p 80,8080,443 -i en1 --nmap"
    echo "  ./enum.sh targets.csv -p 20,21,135,139,445-i eth0 --nmap-full"
    echo "  ./enum.sh targets.csv -p -a -i p1p2"
    exit 1
fi


# First, verify target list.  Convert hostnames to IPs if required

# Parse port list could probably use more verfication...
# It's weird that we don't set PORTS to the top 100 directly...
if [ "-a" = $3  ]; then
    echo "WARNING: Using -a will drastically increase execution time."
    echo "         This will run 100 zmap scans for each IP in the target file"
    
    PORTLIST="80,631,161,137,123,138,1434,445,135,67,23,53,443,21,139,22,500,\
    68,520,1900,25,4500,514,49152,162,69,5353,111,49154,3389,110,1701,998,\
    996,997,999,3283,49153,445,1812,136,139,143,53,2222,135,3306,2049,32768,\
    5060,8080,1025,1433,3456,80,1723,111,995,993,20031,1026,7,5900,1646,\
    1645,593,1025,518,2048,626,1027,587,177,1719,427,497,8888,8888,4444,\
    1023,65024,199,19,9,49193,1029,1720,49,465,88,1028,17185,1718,49186,548,\
    113,81,6001,2000,10000"

else
    PORTLIST=$3
fi
PORTS=$(echo "$PORTLIST" | tr , "\n")

# Should verify interface here...


# Set up BOOL for nmap stuff
NMAP=false
FULLNMAP=false
if [ -z $6 ]; then
    echo "Skipping nmap scan."
    echo "------------------------------------------------------------"
elif [ "--nmap" = $6 ]; then
    echo "nmapping zmap results!"
    echo "------------------------------------------------------------"
    NMAP=true
elif [ "--nmap-full" = $6 ]; then
    echo ""
    echo "WARNING: Using --nmap-full will drastically increase execution time."
    echo "         This will run nmap scans against every IP in the target file"
    echo "------------------------------------------------------------"
    FULLNMAP=true
fi

# Remove anything left over from any previous runs
rm -rf /tmp/enum*.csv
rm -rf IPs2Hostnames.csv
rm -rf zmapSorted.csv
rm -rf digStuff.csv
rm -rf Hostnames.csv
rm -rf nmapScans/

# Generate blacklist for zmap
# Done this way to provide portability and ease of configuration
BLACKLIST=(
    127.0.0.0/8         # RFC1122: Loopback
    192.0.2.0/24        # RFC5737: Documentation (TEST-NET-1)
    192.88.99.0/24      # RFC3068: 6to4 Relay Anycast
    192.168.0.0/16      # RFC1918: Private-Use
    192.18.0.0/15       # RFC2544: Benchmarking
    198.51.100.0/24     # RFC5737: Documentation (TEST-NET-2)
    203.0.113.0/24      # RFC5737: Documentation (TEST-NET-3)
    240.0.0.0/4         # RFC1112: Reserved
    255.255.255.255/32  # RFC0919: Limited Broadcast

    224.0.0.0/4         # RFC5771: Multicast/Reserved
    )
printf "%s\n" "${BLACKLIST[@]}" > /tmp/enumBlacklist.csv

# Perform zmap scans
for PORT in $PORTS; do
    zmap --whitelist-file=$1 --blacklist-file=/tmp/enumBlacklist.csv\
    --interface=$5 --bandwidth=10M  --target-port=$PORT\
    --output-file=/tmp/enum${PORT}.csv
    # Need to update with full path! Everywhere in here
done

# Parse the zmap results
for PORT in $PORTS; do
    cat /tmp/enum${PORT}.csv >> /tmp/enumFull.csv
done
sort -u /tmp/enumFull.csv > zmapSorted.csv

# DNS Enumeration ( Will update to use DNSRecon and other tools)
while read IP; do
    DNSRES=$(dig -x $IP +short)
    # Create a list of hostnames, and a mapping
    echo $DNSRES >> Hostnames.csv
    echo $IP = $DNSRES >> IPs2Hostnames.csv
    # Deeper digging
    #dig +nocmd $IP ANY +noall +answer >> digStuff.csv
done <zmapSorted.csv 

# Something after here breaks, sometimes...

# Nmap scan zmap results if requested
if [ $NMAP ]; then
    mkdir nmapScans/
    echo "nmap -p- -Pn --version-intensity 5 -A -sC -sV -iL zmapSorted.csv -oN nmapScans/"
# Nmap scan full range if requested
elif [ $FULLNMAP ]; then
    mkdir nmapScans/
    echo "nmap -p- -Pn --version-intensity 5 -A -sC -sV -iL $2 -oN nmapScans/"
fi

# Output footer
echo "------------------------------------------------------------"
echo ""
echo "Enumeration script done.  Results as follows:"
echo ""
echo "  zmapSorted.csv:     The consolidated results of the zmap scans"
echo "  IPs2Hostnames.csv:  A link between IPs and their hostnames"
echo "  digStuff.csv:       dig results of the found hostnames"
echo "  nmapScans/:         Full nmap scans of the IPs"

import ipaddress
import argparse
import shodan
import os
import json

def writeToFile(file,line):
    file1 = open(file, "a")  # append mode
    file1.write(line +  "\n")
    file1.close()     

def getAddressData(address):
    #print(address)
    response = api.search('net:'+address)
    #response = api.search('net:'+str(int_addr.network))
    #print (json.dumps(response, indent=4))
    for matches in response["matches"]:
        city = matches["location"]["city"]
        country = matches["location"]["country_name"]
        org = matches["org"]
        isp = matches["isp"]
        ip_addr = str(matches["ip_str"])
        
        port = (matches["transport"] + ":" + str(matches["port"]))
        service_description = (matches["_shodan"]["module"])
        data = (matches["data"])
        messageLine = (ip_addr + ","+ org + ","+ country + ","+ city + ","+ isp + ","+ port + ","+ service_description)
        print(messageLine)
        if args.outputFile:
            writeToFile(str(args.outputFile), messageLine)
        #print(ip_addr,org,country,city,isp,port,service_description,sep=",")
        if "vulns" in matches:
            print("Vulns found!!")
            vulnlist=""
            for vulnerability in matches["vulns"]:
                cvss = (matches["vulns"][vulnerability]["cvss"])
                summary = (matches["vulns"][vulnerability]["summary"])
                #print(vulnerability + " CVSS: " + str(cvss))
                vulnlist = vulnlist + vulnerability + " CVSS: " + str(cvss) +" "
            print(vulnlist)
            if args.outputFile:
                writeToFile(str(args.outputFile),vulnlist)
                
parser = argparse.ArgumentParser()
parser.add_argument('-a','--addresstocheck', help='Host address in ipaddress/subnet CIDR format', required=False, default=False)
parser.add_argument('-i','--inputFile', help='File containing IP info (one ip/net per line)', required=False, default=False)
parser.add_argument('-o','--outputFile', help='File containing IP info (one ip/net per line)', required=False, default=False)
parser.add_argument('-k','--ApiKey', help='Shodan API key', required=False, default=False)
args = parser.parse_args()

#create shodan object
if args.ApiKey:
    # Drop your shodan key here, or pass it with -k at runtime
    api = shodan.Shodan(ApiKey)
else:
    api = shodan.Shodan('{api key here}}')

#Do stuff
if args.inputFile:
    with open(args.inputFile) as iplist_file:
        for line in iplist_file:
            int_addr = ipaddress.ip_interface(line)
            getAddressData(line) 

if args.addresstocheck:
    int_addr = ipaddress.ip_interface(args.addresstocheck)
    getAddressData(str(int_addr.network))


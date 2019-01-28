#!/usr/bin/env python
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# ThreatGridFeedImporter.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 1.0
# Release Date: 01/28/2019
#
# Summary
# -------
#
#   This script will take IoC data from Threat Grid feeds and import it into Stealthwatch host groups.
#   Once data is imported, set a Custom Security Event (CSE) in Stealthwatch to monitor for flows to the imported groups.
#
# Requirements
# ------------
#
#   1) Must have Python 3.x installed.
#   2) Install the required packages from requirements.txt
#       - You'll probably want to set up a virtual environment (https://docs.python.org/3/tutorial/venv.html)
#       - pip install -r requirements.txt
#   3) Must have API access to Threat Grid
#   4) Must have API access to Stealthwatch
#
# How To Run
# ----------
#
#   1) Create a parent host group in Stealthwatch to hold all of the IP feed data.
#       - Grab the Host Group ID from Stealthwatch
#   2) Enter the Host Group ID into SW_PARENT_HOST_GROUP
#   3) Enter your Threat Grid API Key into THREAT_GRID_API_KEY
#   4) Optionally, enter SW_SMC_ADDRESS, SW_USERNAME, SW_PASSWORD
#       - You'll get prompted for them if they're empty
#   2) Run this script with Python 3.x
#
############################################################

import datetime
import getpass
import json
import xml.etree.ElementTree

import requests

from requests.packages import urllib3
from requests.auth import HTTPBasicAuth

# If receiving SSL Certificate Errors, un-comment the line below
urllib3.disable_warnings()

####################
#  CONFIGURATION   #
####################
#
# ---------------------------------------------------- #
#

# Setup an API session
API_SESSION = requests.Session()

# Days of feed data to collect
DAYS_OF_DATA = 7

# Threat Grid Feed URL
THREAT_GRID_FEED_URL = "https://panacea.threatgrid.com/api/v3/feeds"

# Threat Grid Feed ID / Host Group Name Mapping
THREAT_GRID_FEEDS = {
    "autorun-registry": "Autorun Registry Malware",
    "banking-dns": "Banking Trojans",
    "dga-dns": "Domain Generation Algorithm Destinations",
    "dll-hijacking-dns": "DLL Hijackers / Sideloaders",
    "doc-net-com-dns": "Document File Network Communication",
    "downloaded-pe-dns": "Dropper Communication",
    "dynamic-dns": "Dynamic DNS Communication",
    "irc-dns": "IRC Communication",
    "modified-hosts-dns": "Modified HOSTS File Communication",
    "public-ip-check-dns": "Public IP Checkers",
    "ransomware-dns": "Ransomware Communication",
    "rat-dns": "Remote Access Trojans",
    "scheduled-tasks": "Scheduled Task Communication",
    "sinkholed-ip-dns": "Sinkholed IPs",
    "stolen-cert-dns": "Stolen Certificates",
}

# Threat Grid API Key
THREAT_GRID_API_KEY = ""

# Stealthwatch SMC Variables
SW_DOMAIN_ID = None
SW_SMC_ADDRESS = ""
SW_USERNAME = ""
SW_PASSWORD = ""

# Stealthwatch Host Group
SW_PARENT_HOST_GROUP = 0

#
# ---------------------------------------------------- #


####################
#    FUNCTIONS     #
####################


def getAccessToken():
    '''Get REST API Token'''

    print("Authenticating to Stealthwatch...")

    # The URL to authenticate to the SMC
    url = "https://{}/token/v2/authenticate".format(SW_SMC_ADDRESS)

    print("Stealthwatch Authentication URL: {}".format(url))

    # JSON to hold the authentication credentials
    login_credentials = {
        "username": SW_USERNAME,
        "password": SW_PASSWORD
    }

    try:
        # Make an authentication request to the SMC
        response = API_SESSION.post(url, data=login_credentials, verify=False)

        # If the request was successful, then proceed
        if response.status_code == 200:
            print("Successfully Authenticated.")
            return response.text
        else:
            print("SMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(response.status_code, response.text))
            exit()

    except Exception as err:
        print("Unable to post to the SMC - Error: {}".format(err))
        exit()


def getTenants():
    '''Get the "tenants" (domains) from Stealthwatch'''

    print("Fetching Stealthwatch Tenants...")

    global SW_DOMAIN_ID

    # The URL to get tenants
    url = "https://{}/sw-reporting/v1/tenants/".format(SW_SMC_ADDRESS)

    print("Stealthwatch Tenant URL: {}".format(url))

    # Get the tenants
    response = API_SESSION.get(url, verify=False)

    # If the request was successful, then proceed
    if response.status_code == 200:

        # Parse the response as JSON
        tenants = json.loads(response.text)
        tenants = tenants['data']

        # Set the Domain ID if theres only one, or prompt the user if there are multiple
        if len(tenants) == 1:
            SW_DOMAIN_ID = tenants[0]['id']
        else:
            selected_item = selection_list('Domain', 'displayName', tenants)
            SW_DOMAIN_ID = selected_item['id']

    else:
        print("SMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(response.status_code, response.text))
        exit()


def getHostGroupsXML():
    '''A function to build getHostGroups XML for the SMC'''

    return_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    return_xml += "<soapenc:Envelope xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/envelope/\">\n"
    return_xml += "\t<soapenc:Body>\n"
    return_xml += "\t\t<getHostGroups>\n"
    return_xml += "\t\t\t<domain id=\"{}\" />\n".format(SW_DOMAIN_ID)
    return_xml += "\t\t</getHostGroups>\n"
    return_xml += "\t</soapenc:Body>\n"
    return_xml += "</soapenc:Envelope>"

    return return_xml


def addHostGroupXML(ip_list, group_name):
    '''A function to build addHostGroup XML for the SMC'''

    return_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    return_xml += "<soapenc:Envelope xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/envelope/\">\n"
    return_xml += "\t<soapenc:Body>\n"
    return_xml += "\t\t<addHostGroup>\n"
    return_xml += "\t\t\t<host-group domain-id=\"{}\" name=\"{}\" parent-id=\"{}\">\n".format(SW_DOMAIN_ID, group_name, SW_PARENT_HOST_GROUP)

    for ip in ip_list:
        return_xml += "\t\t\t\t<ip-address-ranges>{}</ip-address-ranges>\n".format(ip)

    return_xml += "\t\t\t</host-group>\n"
    return_xml += "\t\t</addHostGroup>\n"
    return_xml += "\t</soapenc:Body>\n"
    return_xml += "</soapenc:Envelope>"

    return return_xml


def setHostGroupIPRangeXML(ip_list, group_id):
    '''A function to build setHostGroupIPRange XML for the SMC'''

    return_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    return_xml += "<soapenc:Envelope xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/envelope/\">\n"
    return_xml += "\t<soapenc:Body>\n"
    return_xml += "\t\t<setHostGroupIPRange>\n"
    return_xml += "\t\t\t<host-group id=\"{}\" domain-id=\"{}\">\n".format(group_id, SW_DOMAIN_ID)

    for ip in ip_list:
        return_xml += "\t\t\t\t<ip-address-ranges>{}</ip-address-ranges>\n".format(ip)

    return_xml += "\t\t\t</host-group>\n"
    return_xml += "\t\t</setHostGroupIPRange>\n"
    return_xml += "\t</soapenc:Body>\n"
    return_xml += "</soapenc:Envelope>"

    return return_xml


def submitXMLToSMC(xml):
    '''A function to post supplied XML to the SMC'''

    # Build the SMC URL
    SMC_URL = "https://{}/smc/swsService/configuration".format(SW_SMC_ADDRESS)

    # Build HTTP Authentication Instance
    auth = HTTPBasicAuth(SW_USERNAME, SW_PASSWORD)

    print("Posting data to the SMC...")

    # Try to make the POST, else print the error
    try:
        # Make the POST request
        http_req = requests.post(url=SMC_URL, auth=auth, data=xml, verify=False)

        # Check to make sure the POST was successful
        if http_req.status_code == 200:
            print("Success.")
            return http_req.text
        else:
            print("SMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(http_req.status_code, http_req.json()))
            exit()

    except Exception as err:
        print("Unable to post to the SMC - Error: {}".format(err))
        exit()


def is_public_ip(ip_string):
    '''This is a function to check whether an IP is public'''

    # Split the octets of the IP
    ip_list = ip_string.split('.')

    # Check to make sure it was IPv4 - if not, fail open
    if len(ip_list) != 4:
        print("The provided IP wasn't IPv4 (IPv6?)")
        return True

    # Check for 10.0.0.0/8
    if int(ip_list[0]) == 10:
        return False

    # Check for 172.16.0.0/12
    if (int(ip_list[0]) == 172) and (16 <= int(ip_list[1]) <= 31):
        return False

    # Check for 192.168.0.0/16
    if (int(ip_list[0]) == 192) and (int(ip_list[1]) == 168):
        return False

    # Check for Localhost
    if int(ip_list[0]) == 127:
        return False

    # Check for Multicast
    if 224 <= int(ip_list[0]) <= 239:
        return False

    # Check for 0.0.0.0
    if int(ip_list[0] == 0) and int(ip_list[1] == 0) and int(ip_list[2] == 0) and int(ip_list[3] == 0):
        return False

    # Check for Broadcast
    if int(ip_list[0] == 255) and int(ip_list[1] == 255) and int(ip_list[2] == 255) and int(ip_list[3] == 255):
        return False

    return True


def selection_list(item_name, item_name_key, item_dict):
    '''This is a function to allow users to select an item from a dict.'''

    print("\nPlease select one of the following {}s:\n".format(item_name))

    index = 1

    # Print the options that are available
    for item in item_dict:
        print("{}) {}".format(index, item[item_name_key]))
        index += 1

    # Prompt the user for the item
    selected_item = input("\n{} Selection: ".format(item_name))

    # Make sure that the selected item was valid
    if 0 < int(selected_item) <= len(item_dict):
        selected_item = int(selected_item) - 1
    else:
        print("ERROR: {} selection was not correct.".format(item_name))
        exit()

    return item_dict[selected_item]


####################
# !!! DO WORK !!!  #
####################


if __name__ == "__main__":
    '''Gather IPs from all Threat Grid feeds and import them into Stealthwatch'''

    # If not hard coded, get the SMC IP, Username and Password
    if not SW_SMC_ADDRESS:
        SW_SMC_ADDRESS = input("SMC IP/FQDN Address: ")
    if not SW_USERNAME:
        SW_USERNAME = input("SMC Username: ")
    if not SW_PASSWORD:
        SW_PASSWORD = getpass.getpass("SMC Password: ")

    # If a Domain ID wasn't specified, then get one
    if SW_DOMAIN_ID is None:

        # Authenticate to REST API
        getAccessToken()

        # Get Tenants from REST API
        getTenants()

    # Get the Host Groups XML from StealthWatch
    host_groups_xml = submitXMLToSMC(getHostGroupsXML())

    # Parse the Host Group XML settings
    root = xml.etree.ElementTree.fromstring(host_groups_xml.encode('ascii', 'ignore'))

    # Get the Parent Host Group that was specified
    parent_host_group = root.find(".//{http://www.lancope.com/sws/sws-service}host-group[@id=\"" + str(SW_PARENT_HOST_GROUP) + "\"]")

    # Iterate through all of the specified Threat Grid feeds
    for feed_name, host_group_name in THREAT_GRID_FEEDS.items():

        # Iterate through each day
        # this is needed because of the new Feed API format
        for day in range(DAYS_OF_DATA):

            # Get a timestamp for X days ago
            timestamp = datetime.datetime.utcnow().date() - datetime.timedelta(days=day)

            # Construct the URL to be used
            url = "{}/{}_{}.json?api_key={}".format(THREAT_GRID_FEED_URL, feed_name, timestamp, THREAT_GRID_API_KEY)

            print(url)

            # Construct the HTTP Headers
            request_headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

            # Make the API call
            response = API_SESSION.get(url, headers=request_headers)

            # Parse the response
            json_response = json.loads(response.content)

            ip_list = []

            # Iterate through each IoC in the reponse
            for ioc in json_response:

                # Iterate through each IP in the IoC
                for ip in ioc['ips']:

                    # Check to make sure the IP is public
                    if is_public_ip(ip):

                        # Append the IP to our list (Stealthwatch will de-dupe this later)
                        ip_list.append(ip)

        # Set a placeholder Host Group ID
        host_group_id = None

        try:
            # Iterate through all of the children of the parent host group
            for child_host_group in parent_host_group.findall(".//{http://www.lancope.com/sws/sws-service}host-group"):

                # If the host group name matches, then use it
                if host_group_name.lower() in child_host_group.get('name').lower():
                    host_group_id = child_host_group.get('id')
        except:
            print("\033[1;31mUnable to locate either the Domain ID or Host Group ID - Please check the config section of the script.\033[1;m")
            exit()

        # If there's an existing host group, then update, otherwise create a new one
        if host_group_id is None:
            print("Submitting XML to the SMC for {} and creating a new group".format(host_group_name))
            submitXMLToSMC(addHostGroupXML(ip_list, host_group_name))
        else:
            print("Submitting XML to the SMC for {} and group ID {}".format(host_group_name, host_group_id))
            submitXMLToSMC(setHostGroupIPRangeXML(ip_list, host_group_id))

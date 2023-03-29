#!/usr/bin/env python3

# Write me a python 3 script that uses multiple functions to break up the following instructions logically: that read a filename from a command line argument and then loads that file into a dictionary variable called json_data and closes the file handle. Check if json_data["GSD"]["reporter"] is equal to joshbressers and json_data["GSD"]["vendor_name"] is equal to Linux and json_data["GSD"]["product_name"] is equal to Kernel and if they are NOT exit immediately. Then create a new python dictionary called gsd_data and add a key called gsd with a value of an empty dictionary. Then take json_data and check for a key called OSV, if it exists move the contents of OSV into gsd_data["gsd"]["osvSchema"] and delete json_data["OSV"]. Then add a key in gsd_data["gsd"]["osvSchema"]["schema_version"] with a value of "1.4.0". Then add a key in gsd_data called metadata with an empty dictionary as the value. Then move the key and value json_data["GSD"]["reporter"] to gsd_data["metadata"]. Then move the key and value json_data["GSD"]["reporter_id"] to gsd_data["metadata"]. Then check if json_data["GSD"]["vendor_name"] is equal to gsd_data["gsd"]["osvSchema"]["affected"][0]["package"]["ecosystem"] and if it is delete json_data["GSD"]["vendor_name"]. Then check if json_data["GSD"]["product_name"] is equal to gsd_data["gsd"]["osvSchema"]["affected"][0]["package"]["name"] and if it is delete json_data["GSD"]["product_name"]. Then take json_data["GSD"]["product_version"] and split the string into two pieces, the first value starting with "versions from " and call it introduced_in and the second value starting with " to before " and call it fixed_in. If introduced_in is blank set it to "0". If fixed_in is blank set it to "*". Create a new dictionary value in gsd_data["gsd"]["osvSchema"]["affected"]["ranges"] with a key called "type" and a value of "SEMVER". Then create a a new key called "events" with a value of an empty list. Write a key called "introduced" with the value from introduced_in to the list.  Write a key called "fixed" with the value from fixed_in to the list.  

# Then some more functions and hand editing

import sys
import json
import re
from datetime import datetime, timezone

def load_json_data(filename):
    with open(filename, 'r') as f:
        return json.load(f)

def check_gsd_data(json_data):
    if (json_data["GSD"]["reporter"] != "joshbressers" or
        json_data["GSD"]["vendor_name"] != "Linux" or
        json_data["GSD"]["product_name"] != "Kernel"):
        sys.exit()

def create_gsd_data(json_data):
    gsd_data = {"gsd": {"osvSchema": {}}, "metadata": {}}
    if "OSV" in json_data:
        gsd_data["gsd"]["osvSchema"] = json_data["OSV"]
        del json_data["OSV"]
    gsd_data["gsd"]["osvSchema"]["schema_version"] = "1.4.0"
    gsd_data["metadata"]["reporter"] = json_data["GSD"]["reporter"]
    del json_data["GSD"]["reporter"]
    gsd_data["metadata"]["reporter_id"] = json_data["GSD"]["reporter_id"]
    del json_data["GSD"]["reporter_id"]
    if json_data["GSD"]["vendor_name"] == gsd_data["gsd"]["osvSchema"]["affected"][0]["package"]["ecosystem"]:
        del json_data["GSD"]["vendor_name"]
    if json_data["GSD"]["product_name"] == gsd_data["gsd"]["osvSchema"]["affected"][0]["package"]["name"]:
        del json_data["GSD"]["product_name"]

    introduced_in, fixed_in = split_version_string(json_data["GSD"]["product_version"])

    gsd_data["gsd"]["osvSchema"]["affected"][0]["ranges"].append({"type": "SEMVER", "events": []})
    gsd_data["gsd"]["osvSchema"]["affected"][0]["ranges"][1]["events"].append({"introduced": introduced_in})
    gsd_data["gsd"]["osvSchema"]["affected"][0]["ranges"][1]["events"].append({"fixed": fixed_in})
    del json_data["GSD"]["product_version"]

    if json_data["GSD"]["credit"] == "":
        del json_data["GSD"]["credit"]
    
    if json_data["GSD"]["notes"] == "":
        del json_data["GSD"]["notes"]

    if json_data["GSD"]["description"] == gsd_data["gsd"]["osvSchema"]["details"]:
        del json_data["GSD"]["description"]

    # HANDLE REFERENCES 

    if "references" not in gsd_data["gsd"]["osvSchema"]:
        gsd_data["gsd"]["osvSchema"]["references"] = []

    for url in json_data["GSD"]["references"]:
        for ref in json_data["GSD"]["extended_references"]:
            if url.endswith(ref["value"]):
                if ref["note"] == "introduced":
                    entry = {}
                    entry["type"] = "INTRODUCED"
                    entry["url"] = url
                    gsd_data["gsd"]["osvSchema"]["references"].append(entry)
                elif ref["note"] == "fixed":
                    entry = {}
                    entry["type"] = "FIX"
                    entry["url"] = url
                    gsd_data["gsd"]["osvSchema"]["references"].append(entry)
                else:
                    entry = {}
                    entry["type"] = "WEB"
                    entry["url"] = url
                    gsd_data["gsd"]["osvSchema"]["references"].append(entry)
    del json_data["GSD"]["references"]
    del json_data["GSD"]["extended_references"]


    # Deal with other random bits
    if "database_specific" not in gsd_data["gsd"]["osvSchema"]:
        gsd_data["gsd"]["osvSchema"]["database_specific"] = {}

    if "vulnerability_type" in json_data["GSD"]:
        gsd_data["gsd"]["osvSchema"]["database_specific"]["vulnerability_type"] = json_data["GSD"].pop("vulnerability_type")
    if "affected_component" in json_data["GSD"]:
        gsd_data["gsd"]["osvSchema"]["database_specific"]["affected_component"] = json_data["GSD"].pop("affected_component")
    if "attack_vector" in json_data["GSD"]:
        gsd_data["gsd"]["osvSchema"]["database_specific"]["attack_vector"] = json_data["GSD"].pop("attack_vector")
    if "impact" in json_data["GSD"]:
        gsd_data["gsd"]["osvSchema"]["database_specific"]["impact"] = json_data["GSD"].pop("impact")

    if json_data["GSD"] == {}:
        del json_data["GSD"]
  
  # any remaining data MUST be handled so bail out.
    if json_data != {}:
        print("ERROR: UNHANDLED DATA LEFT OVER")
        print(json.dumps(json_data, indent=2))
        sys.exit()

    gsd_data["gsd"]["osvSchema"]["modified"] = print_current_time_rfc3339()

    return gsd_data

def split_version_string(version_string):
    # Split the version string into two parts based on "versions from" and "to before"
    parts = version_string.split(" to before ")

    if parts[0] == "versions from ":
        introduced_in = "0"
    else:
        introduced_in = re.sub("^versions from v", "", parts[0])

    if parts[1] == "":
        fixed_in = "*"
    else:
        fixed_in = re.sub("^v", "", parts[1])
    
    # Return the extracted values
    return(introduced_in, fixed_in)

def print_current_time_rfc3339():
    now = datetime.now(timezone.utc)
    rfc3339_time = now.isoformat(timespec='seconds')
    return(rfc3339_time)

def write_dict_to_json_file(dict_data, file_path):
    with open(file_path, 'w') as file:
        json.dump(dict_data, file, indent=2)

if __name__ == "__main__":
    filename = sys.argv[1]
    json_data = load_json_data(filename)
    check_gsd_data(json_data)
    gsd_data = create_gsd_data(json_data)
    write_dict_to_json_file(gsd_data, filename)

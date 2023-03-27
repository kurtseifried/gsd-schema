#!/usr/bin/env python3

import sys
import json

# load json_data from file
with open(sys.argv[1], 'r') as json_file:
    json_data = json.load(json_file)

# check if vendor_name, product_name and reporter match
if (json_data["GSD"]["vendor_name"] != "Linux" 
    or json_data["GSD"]["product_name"] != "Kernel" 
    or json_data["GSD"]["reporter"] != "joshbressers"):
    sys.exit()

# create gsd_data dictionary
gsd_data = {}

# load OSV data into gsd_data
gsd_data["gsd"] = {}
gsd_data["gsd"]["osvSchema"] = json_data["OSV"]

# write schema_version
gsd_data["gsd"]["osvSchema"]["schema_version"] = "1.4.0"

# write reporter and reporter_id to metadata
gsd_data["gsd"]["metadata"] = {}
gsd_data["gsd"]["metadata"]["reporter"] = json_data["GSD"]["reporter"]
gsd_data["gsd"]["metadata"]["reporter_id"] = json_data["GSD"]["reporter_id"]

# loop through affected packages and write SEMVER info if it doesn't exist
for affected in gsd_data["gsd"]["osvSchema"]["affected"]:
    for range_item in affected["ranges"]:
        if "type" in range_item and range_item["type"] == "SEMVER":
            break
    else:
        semver_info = {}
        product_version = json_data["GSD"]["product_version"]
        if "versions from" in product_version:
            semver_info["introduced"] = product_version.split("versions from ")[1].split(" to before ")[0]
        if "to before" in product_version:
            semver_info["fixed"] = product_version.split("to before ")[1]
        affected["ranges"].append({"type": "SEMVER", "semver": semver_info})

# write metadata
gsd_data["gsd"]["metadata"]["type"] = "concern"
gsd_data["gsd"]["metadata"]["exploitCode"] = "unknown"
gsd_data["gsd"]["metadata"]["remediation"] = "official"
gsd_data["gsd"]["metadata"]["reportConfidence"] = "confirmed"

if "vulnerability_type" in json_data["GSD"]:
    gsd_data["gsd"]["metadata"]["vulnerability_type"] = json_data["GSD"]["vulnerability_type"]
if "affected_component" in json_data["GSD"]:
    gsd_data["gsd"]["metadata"]["affected_component"] = json_data["GSD"]["affected_component"]
if "attack_vector" in json_data["GSD"]:
    gsd_data["gsd"]["metadata"]["attack_vector"] = json_data["GSD"]["attack_vector"]
if "impact" in json_data["GSD"]:
    gsd_data["gsd"]["metadata"]["impact"] = json_data["GSD"]["impact"]

# print the resulting dictionary
# Print the resulting gsd_data
print(json.dumps(gsd_data, indent=2))

#!/usr/bin/env python3

import sys
import json

def main(json_file):
    with open(json_file, 'r') as f:
        json_data = json.load(f)

    if (
        json_data.get("GSD", {}).get("vendor_name") != "Linux"
        or json_data.get("GSD", {}).get("product_name") != "Kernel"
        or json_data.get("GSD", {}).get("reporter") != "joshbressers"
    ):
        sys.exit(0)

    gsd_data = {}
    gsd_data["gsd"] = {}
    gsd_data["gsd"]["osvSchema"] = json_data.pop("OSV")
    gsd_data["gsd"]["osvSchema"]["schema_version"] = "1.4.0"

    gsd_data["gsd"]["metadata"] = {}
    gsd_data["gsd"]["metadata"]["reporter"] = json_data["GSD"].pop("reporter")
    gsd_data["gsd"]["metadata"]["reporter_id"] = json_data["GSD"].pop("reporter_id")

    for item in gsd_data["gsd"]["osvSchema"]["affected"]:
        if "ranges" in item:
            for range_item in item["ranges"]:
                if range_item.get("type") != "SEMVER":
                    range_item["type"] = "SEMVER"

            product_version = json_data["GSD"]["product_version"]
            introduced, fixed = product_version.split("to before")
            introduced = introduced.replace("versions from", "").strip()
            fixed = fixed.strip()

            if introduced:
                range_item["introduced"] = introduced
            if fixed:
                range_item["fixed"] = fixed

    gsd_data["gsd"]["metadata"]["type"] = "concern"
    gsd_data["gsd"]["metadata"]["exploitCode"] = "unknown"
    gsd_data["gsd"]["metadata"]["remediation"] = "official"
    gsd_data["gsd"]["metadata"]["reportConfidence"] = "confirmed"

    if "vulnerability_type" in json_data["GSD"]:
        gsd_data["gsd"]["metadata"]["vulnerability_type"] = json_data["GSD"].pop("vulnerability_type")

    if "affected_component" in json_data["GSD"]:
        gsd_data["gsd"]["metadata"]["affected_component"] = json_data["GSD"].pop("affected_component")

    if "attack_vector" in json_data["GSD"]:
        gsd_data["gsd"]["metadata"]["attack_vector"] = json_data["GSD"].pop("attack_vector")

    if "impact" in json_data["GSD"]:
        gsd_data["gsd"]["metadata"]["impact"] = json_data["GSD"].pop("impact")


    del json_data["GSD"]["vendor_name"] 
    del json_data["GSD"]["product_name"] 
    del json_data["GSD"]["product_version"]
    del json_data["GSD"]["credit"]
    del json_data["GSD"]["notes"]
    del json_data["GSD"]["description"]
    del json_data["GSD"]["extended_references"] 

    gsd_data["gsd"]["osvSchema"]["references"] = process_references(json_data)
    del json_data["GSD"]["references"]
    
    # Check if "GSD" is empty, delete it if so
    if json_data.get("GSD") == {}:
        del json_data["GSD"]
    else:
        print("GSD is not empty. Quitting.")
        sys.exit()
    return gsd_data



def process_references(json_data):
    # Step 1: Create a new list for references
    references = []

    # Step 2: Iterate through "references" in "json_data"
    for ref in json_data["GSD"]["references"]:
        if isinstance(ref, str) and ref.startswith("https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/"):
            # Step 3: Create a new dictionary for the reference
            reference = {"type": "FIX", "url": ref}
            references.append(reference)

    # Return the list of references
    return references


if __name__ == "__main__":
    if len(sys.argv) > 1:
        gsd_data = main(sys.argv[1])
        with open(sys.argv[1], "w") as f:
            json.dump(gsd_data, f, indent=2)

    else:
        print("Usage: python script.py <json_file>")

        

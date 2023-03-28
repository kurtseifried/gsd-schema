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

    print("####")
    print(json.dumps(json_data, indent=2))
    print("####")
    print(json.dumps(gsd_data, indent=2))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        print("Usage: python script.py <json_file>")

        

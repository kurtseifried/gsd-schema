#!/usr/bin/env python3

ype"] == "SEMVER":
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
                                                                        print(gsd_data)~
                                                                        

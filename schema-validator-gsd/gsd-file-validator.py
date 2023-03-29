#!/usr/bin/env python3

# This validator checks a file and checks it against the appropriate schema and tells if it 
# passes or not and what problems it had, if any

# TODO: jsonschema load files locally? https://python-jsonschema.readthedocs.io/en/stable/faq/#how-do-i-configure-a-base-uri-for-ref-resolution-using-local-files


import re
import sys
import os
import json

from jsonschema import validate, ValidationError
from jsonschema.exceptions import SchemaError

################################################################################
# Write me a python script that takes a command line argument of a filename, strips the path and leaves just the filename and then checks if the filename starts with GSD-NNNN- where NNNN is a year and returns "gsd" if it is, or if the filename starts with CVE-NNNN- where NNNN is a year and returns "cve" if it is, or if the filename is "GHSA-AAAA-AAAA-AAAA" where AAAA is numbers and/or lower case letters and returns "ghsa" if it is
# TODO: better GSD/CVE filename detection
# 
def check_filename(filename):
    gsd_pattern = r'^GSD-\d{4}-'
    cve_pattern = r'^CVE-\d{4}-'
    ghsa_pattern = r'^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$'

    if re.match(gsd_pattern, filename):
        return "gsd"
    elif re.match(cve_pattern, filename):
        return "cve"
    elif re.match(ghsa_pattern, filename):
        return "ghsa"
    else:
        return "Invalid filename format"

def extract_filename(path):
    return os.path.basename(path)

################################################################################
# write a python function that opens a JSON file and loads it into a global dictionary called json_data. then check if json_data["gsd"]["osvSchema"]["schema_version"] exists and if it does assign the value to  a variable called "osv_schema_version", then create a new variable called schema_filename that is equal to schema-OSV_{osv_schema_version}.json
#
def get_OSV_schema_filename(filename):
    global json_data
    with open(filename) as f:
        json_data = json.load(f)

    if "schema_version" in json_data["gsd"]["osvSchema"]:
        osv_schema_version = json_data["gsd"]["osvSchema"]["schema_version"]
        schema_filename = f"schema-OSV_" + osv_schema_version + ".json"
    return schema_filename


################################################################################
# write me a python function called check_osvSchema that takes a python dictionary and a JSON schema filename and then checks the JSON data array against the JSON schema file, if the schema checks ok return a string saying "validated" and if there are any errors please print them and then return a string saying "failed"

# write me a python function called check_osvSchema that takes a python dictionary and a JSON schema filename, and then creates a full path to the schema file by reading the dictionary in the file ~/.gsdconfig and taking the gsd_tools_path key, adding "/local-scripts/schema-validator-gsd/" to it and then finally adding the filename at the end, and then checks the JSON data array against the JSON schema file, if the schema checks ok return a string saying "validated" and if there are any errors please print them and then return a string saying "failed"


def check_osvSchema(data: dict, schema_filename: str) -> str:
    # gsd_tools_path 
    schema_filename_full = "/Users/kurt/GitHub/gsd-tools/local-scripts/schema-validator-gsd/" + schema_filename
    try:
        with open(schema_filename_full, 'r') as file:
            schema = json.load(file)

        validate(instance=data, schema=schema)
        return "validated"

    except ValidationError as ve:
        print(f"Validation error: {ve.message}")
        return "failed"

    except SchemaError as se:
        print(f"Schema error: {se.message}")
        return "failed"

    except FileNotFoundError:
        print(f"File not found: {schema_filename}")
        return "failed"

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return "failed"




################################################################################
#
# Glue the bits together here
#
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python filename_checker.py <path_to_filename>")
        sys.exit(1)

    path_to_filename = sys.argv[1]
    filename = extract_filename(path_to_filename)
    file_type = check_filename(filename)

    if file_type == "gsd":
        schema_filename = get_OSV_schema_filename(path_to_filename)
        schema_check = check_osvSchema(json_data["gsd"]["osvSchema"], schema_filename)
        print(path_to_filename + " " + schema_check) 
    


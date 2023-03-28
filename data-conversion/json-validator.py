#!/usr/bin/env python3

# json-validator.py <json_file> <schema_file>

import json
import sys
import os
from jsonschema import validate, RefResolver
from urllib.parse import urljoin

def read_json_file(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def create_ref_resolver(schema_path, schema):
    base_uri = 'file://' + os.path.abspath(schema_path)
    resolver = RefResolver(base_uri, schema)
    return resolver

def validate_json(json_data, schema_data, ref_resolver):
    try:
        validate(instance=json_data, schema=schema_data, resolver=ref_resolver)
        print("The JSON file is valid.")
    except Exception as e:
        print("The JSON file is not valid. Error:", e)

def main(json_file, schema_file):
    json_data = read_json_file(json_file)
    schema_data = read_json_file(schema_file)
    ref_resolver = create_ref_resolver(schema_file, schema_data)
    validate_json(json_data, schema_data, ref_resolver)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python json_schema_validator.py <json_file> <schema_file>")
        sys.exit(1)
    json_file = sys.argv[1]
    schema_file = sys.argv[2]
    main(json_file, schema_file)

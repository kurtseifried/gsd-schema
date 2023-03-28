#!/usr/bin/env python3

import json
import jsonschema
import argparse

def validate_json(schema_file, json_file):
    with open(schema_file) as f:
        schema = json.load(f)

    # Use the resolver to resolve any external $ref references
    resolver = jsonschema.RefResolver.from_schema(schema)
    schema = resolver.resolve(schema)

    with open(json_file) as f:
        json_data = json.load(f)

    try:
        jsonschema.validate(json_data, schema)
        print("JSON data is valid!")
    except jsonschema.exceptions.ValidationError as e:
        print(f"Validation error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate JSON data against a JSON schema.")
    parser.add_argument("schema_file", help="Path to the JSON schema file.")
    parser.add_argument("json_file", help="Path to the JSON file to validate.")
    args = parser.parse_args()

    validate_json(args.schema_file, args.json_file)

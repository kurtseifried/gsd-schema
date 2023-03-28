#!/usr/bin/env python3

import json
import jsonschema
import sys

if len(sys.argv) < 3:
    print("Usage: python validate_json.py <data.json> <schema.json>")
    sys.exit(1)

# Load the JSON data and schema files
with open(sys.argv[1], 'r') as f:
    data = json.load(f)

with open(sys.argv[2], 'r') as f:
    schema = json.load(f)

# Create a JSON schema resolver for any references in the schema
resolver = jsonschema.RefResolver.from_schema(schema)

# Validate the data against the schema
try:
    jsonschema.validate(data, schema, resolver=resolver)
    print('Data is valid!')
except jsonschema.exceptions.ValidationError as e:
    print('Data is invalid:')
    print(e)


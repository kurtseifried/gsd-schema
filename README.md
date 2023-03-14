# gsd-schema
The new GSD schema and the tools to support it

# Basic format

```
{
    "gsd": {
        "osv_schema": {},
        "cve4_schema": {},
        "cve5_schema": {}
    },
    "namespaces": {
        "cve.org": {},
        "nvd.nist.gov": {},
        "mozilla.org": {}
    }
}
```

# Notes

The namespaces area stays exactly the same. The gsd area is lowercased, and contains optional metadata (that e.g. doesn't fit into OSV/CVE/etc. data formats). Within gsd we have osv_schema (the first class citizen), and other data schemeas such as cve4_schema, cve5_schema, csaf_schema, vex_schema, openvex_schema, etc.). The reason for this is that not all schemas support all the data types, and to provide rich data we will need multiple data sets. Some schema keys will include a major verison (e.g. CVE v.4 vs. v.5) due to major changes and large amounts of old data that is difficult to update being available.

All entries MUST contain a version tag if one exists (e.g. "schema_version" in OSV). 

# Schema

The schema file for a GSD entry is currently: 

1. in gsd there MUST be an osv_schema and it MUST be correct
2. if there is a secondary data set(s) in gsd it SHOULD be correct (e.g. CVE, CSAF, etc.)
3. if there is a schema for a given namespace it SHOULD be correct

Where possible we will push data bugs to upstreams to get them corrected, this has already been successful (e.g. with Mozilla and Mageia https://bugs.mageia.org/show_bug.cgi?id=30148).

# Spacing

Spacing SHOULD be 2 or 4, if the file already exists, you MUST use the existing spacing (2, 4 or none). 

# Tools

We want a python set of tools for local use on the files (e.g. development workstation, enrichment server, etc.) and a Cloudflare worker set for building out the APIs.

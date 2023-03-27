# Data conversion

Data conversion fo the various existing formats to the new standard format:

https://github.com/cloudsecurityalliance/gsd-tools/blob/main/gsd-schema/validation/schema.json

# Existing formats:

* Linux Kernel entries
* GSD Request form entries
  * Entries with data
  * Duplicates
* CVE v4 Entries
  * CVE PUBLIC
  * CVE RESERVED
  * CVE REJECT

# Conversion of Linux Kernel

```
{
  "GSD": {
    "vendor_name": "Linux",
    "product_name": "Kernel",
    "product_version": "versions from  to before v5.15.89",
    "vulnerability_type": "unspecified",
    "affected_component": "unspecified",
    "attack_vector": "unspecified",
    "impact": "unspecified",
    "credit": "",
    "references": [
      "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=470f6a9175f13a53810734658c35cc5bba33be01"
    ],
    "extended_references": [
      {
        "type": "commit",
        "value": "470f6a9175f13a53810734658c35cc5bba33be01",
        "note": "fixed"
      }
    ],
    "reporter": "joshbressers",
    "reporter_id": 1692786,
    "notes": "",
    "description": "regulator: da9211: Use irq handler when ready\n\nThis is an automated ID intended to aid in discovery of potential security vulnerabilities. The actual impact and attack plausibility have not yet been proven.\nThis ID is fixed in Linux Kernel version v5.15.89 by commit 470f6a9175f13a53810734658c35cc5bba33be01. For more details please see the references link."
  },
  "OSV": {
    "id": "GSD-2023-1002120",
    "modified": "2023-02-13T17:43:01.814336Z",
    "published": "2023-02-13T17:43:01.814336Z",
    "summary": "regulator: da9211: Use irq handler when ready",
    "details": "regulator: da9211: Use irq handler when ready\n\nThis is an automated ID intended to aid in discovery of potential security vulnerabilities. The actual impact and attack plausibility have not yet been proven.\nThis ID is fixed in Linux Kernel version v5.15.89 by commit 470f6a9175f13a53810734658c35cc5bba33be01. For more details please see the references link.",
    "affected": [
      {
        "package": {
          "name": "Kernel",
          "ecosystem": "Linux"
        },
        "ranges": [
          {
            "type": "GIT",
            "repo": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/",
            "events": [
              {
                "introduced": "0"
              },
              {
                "limit": "470f6a9175f13a53810734658c35cc5bba33be01"
              }
            ]
          }
        ]
      }
    ]
  }
}
```

```
{
  "GSD": {
IGNORE:    "vendor_name": "Linux",
IGNORE:    "product_name": "Kernel",
    "product_version": "versions from  to before v5.15.89",
    "vulnerability_type": "unspecified",
    "affected_component": "unspecified",
    "attack_vector": "unspecified",
    "impact": "unspecified",
    "credit": "",
    "references": [
      "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=470f6a9175f13a53810734658c35cc5bba33be01"
    ],
    "extended_references": [
      {
        "type": "commit",
        "value": "470f6a9175f13a53810734658c35cc5bba33be01",
        "note": "fixed"
      }
    ],
GSD:METADATA    "reporter": "joshbressers",
GSD:METADATA    "reporter_id": 1692786,
    "notes": "",
    "description": "regulator: da9211: Use irq handler when ready\n\nThis is an automated ID intended to aid in discovery of potential security vulnerabilities. The actual impact and attack plausibility have not yet been proven.\nThis ID is fixed in Linux Kernel version v5.15.89 by commit 470f6a9175f13a53810734658c35cc5bba33be01. For more details please see the references link."
  },
  "OSV": {
    "id": "GSD-2023-1002120",
    "modified": "2023-02-13T17:43:01.814336Z",
    "published": "2023-02-13T17:43:01.814336Z",
    "summary": "regulator: da9211: Use irq handler when ready",
    "details": "regulator: da9211: Use irq handler when ready\n\nThis is an automated ID intended to aid in discovery of potential security vulnerabilities. The actual impact and attack plausibility have not yet been proven.\nThis ID is fixed in Linux Kernel version v5.15.89 by commit 470f6a9175f13a53810734658c35cc5bba33be01. For more details please see the references link.",
    "affected": [
      {
        "package": {
          "name": "Kernel",
          "ecosystem": "Linux"
        },
        "ranges": [
          {
            "type": "GIT",
            "repo": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/",
            "events": [
              {
                "introduced": "0"
              },
              {
                "limit": "470f6a9175f13a53810734658c35cc5bba33be01"
              }
            ]
          }
        ]
      }
    ]
  }
}
```

# Prompt
```
Write me a Python script that does the following:

1. takes a command line argument of a JSON file and loads it into a variable called "json_data"
2. check to see if json_data["GSD"]["vendor_name"] equals the string "Linux" and if json_data["GSD"]["product_name"] equals "Kernel" and if json_data["GSD"]["reporter"] equals the string "joshbressers", if they are present the script continues, if not the script exits immediately
3. Create a new variable called "gsd_data" that is a blank python dictionary 
4. take the data from json_data["OSV"] and load it into the gsd_data["gsd"]["osvSchema"]
5. write a variable called gsd_data["gsd"]["osvSchema"]["schema_version"] with the string value "1.4.0"
6. write json_data["GSD"]["reporter"] to gsd_data["gsd"]["metadata"]["reporter"]
7. write json_data["GSD"]["reporter_id"] to gsd_data["gsd"]["metadata"]["reporter_id"]
8. the variable gsd_data["gsd"]["osvSchema"]["affected"] is a list of one or more items, loop through this list of items which contains a further list of dictionaries called package, severity, ranges, versions, ecosystem_specific and database_specific. If you find a dictionary called ranges check the list it contains for an item with a key called "type" that has a value of "SEMVER" and if it doesn't exist create a dictionary starting with a key called "type" and a value of "SEMVER". Then take the json_data["GSD"]["product_version"] string and process it as follows: split it into two strings, one starting with "versions from" and the second starting with "to before", if there is a version string in the first "versions from" text please write it to the dictionary as the value for a key called "introduced" and if there is a version string in the first "to before" text please write it to the dictionary as the value for a key called "fixed"

9. Create a new variable called gsd_data["gsd"]["metadata"]["type"] that is the string "concern"
10. Create a new variable called gsd_data["gsd"]["metadata"]["exploitCode"] that is the string "unknown"
11. Create a new variable called gsd_data["gsd"]["metadata"]["remediation"] that is the string "official"
12. Create a new variable called gsd_data["gsd"]["metadata"]["reportConfidence"] that is the string "confirmed"
13. If json_data["GSD"]["vulnerability_type"] exists write it to gsd_data["gsd"]["metadata"]["vulnerability_type"]
14. If json_data["GSD"]["affected_component"] exists write it to gsd_data["gsd"]["metadata"]["affected_component"]
15. If json_data["GSD"]["attack_vector"] exists write it to gsd_data["gsd"]["metadata"]["attack_vector"]
16. If json_data["GSD"]["impact"] exists write it to gsd_data["gsd"]["metadata"]["impact"]

20. print the JSON in gsd_data with 2 spaces for indent

```

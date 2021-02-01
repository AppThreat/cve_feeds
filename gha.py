"""
GitHub Security Advisory to NVD CVE convertor

This simple script fetches the recent security advisories from GitHub and stores them in NVD CVE 1.1 jsonlines format. Below substitutions are made to properly construct the NVD CVE Json

- versionStartIncluding and versionEndIncluding are calculated from version range. Version End is chosen to hold any single version number being passed
- vectorString is constructed based on severity. The official calculator [url](https://www.first.org/cvss/calculator/3.1) was used to construct some realistic strings for given severity
- Full description (description) is ignored for now

"""
import json
import jsonlines
import os
import re

import requests

CVE_TPL = """
{"cve":{"data_type":"CVE","data_format":"MITRE","data_version":"4.0","CVE_data_meta":{"ID":"%(cve_id)s","ASSIGNER":"%(assigner)s"},"problemtype":{"problemtype_data":[{"description":[{"lang":"en","value":"%(cwe_id)s"}]}]},"references":{"reference_data": %(references)s},"description":{"description_data":[{"lang":"en","value":"%(description)s"}]}},"configurations":{"CVE_data_version":"4.0","nodes":[{"operator":"AND","children":[{"operator":"OR","cpe_match":[{"vulnerable":true,"cpe23Uri":"cpe:2.3:a:%(vendor)s:%(product)s:%(version)s:*:*:*:*:*:*:*","versionStartIncluding":"%(version_start)s","versionEndIncluding":"%(version_end)s"}]}]},{"operator":"OR","cpe_match":[{"vulnerable":true,"cpe23Uri":"cpe:2.3:a:%(vendor)s:%(product)s:%(version)s:*:*:*:*:*:*:*"}]}]},"impact":{"baseMetricV3":{"cvssV3":{"version":"3.1","vectorString":"%(vectorString)s","attackVector":"NETWORK","attackComplexity":"%(attackComplexity)s","privilegesRequired":"NONE","userInteraction":"REQUIRED","scope":"UNCHANGED","confidentialityImpact":"%(severity)s","integrityImpact":"%(severity)s","availabilityImpact":"%(severity)s","baseScore":%(score).1f,"baseSeverity":"%(severity)s"},"exploitabilityScore":%(score).1f,"impactScore":%(score).1f},"baseMetricV2":{"cvssV2":{"version":"2.0","vectorString":"AV:N/AC:M/Au:N/C:P/I:P/A:P","accessVector":"NETWORK","accessComplexity":"MEDIUM","authentication":"NONE","confidentialityImpact":"PARTIAL","integrityImpact":"PARTIAL","availabilityImpact":"PARTIAL","baseScore":%(score).1f},"severity":"%(severity)s","exploitabilityScore":%(score).1f,"impactScore":%(score).1f,"acInsufInfo":false,"obtainAllPrivilege":false,"obtainUserPrivilege":false,"obtainOtherPrivilege":false,"userInteractionRequired":false}},"publishedDate":"%(publishedDate)s","lastModifiedDate":"%(lastModifiedDate)s"}
"""

url = "https://api.github.com/graphql"
api_token = os.environ["GITHUB_TOKEN"]
headers = {"Authorization": "token %s" % api_token}
gqljson = {
    "query": """
        query {
            securityAdvisories(first: 100) {
            nodes {
              id
              ghsaId
              summary
              description
              identifiers {
                type
                value
              }
              origin
              publishedAt
              updatedAt
              references {
                url
              }
              severity
              vulnerabilities(first: 10) {
                nodes {
                  firstPatchedVersion {
                    identifier
                  }
                  package {
                    ecosystem
                    name
                  }
                  severity
                  updatedAt
                  vulnerableVersionRange
                }
              }
            }
          }
        }
        """
}

r = requests.post(url=url, json=gqljson, headers=headers)
data = r.json()
jsonldata = []
for cve in data["data"]["securityAdvisories"]["nodes"]:
    cve_id = None
    assigner = "cve@mitre.org"
    references = []

    for r in cve["references"]:
        references.append({"url": r["url"], "name": r["url"]})

    for id in cve["identifiers"]:
        if id["type"] == "CVE":
            cve_id = id["value"]
    if not cve_id:
        cve_id = cve["ghsaId"]
        assigner = "@github"
    for p in cve["vulnerabilities"]["nodes"]:
        vendor = p["package"]["ecosystem"]
        product = p["package"]["name"]
        version = p["vulnerableVersionRange"].lower()
        version = re.sub("[ <>=]", "", version)
        version_start = ""
        version_end = version
        vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        if "," in version:
            versArr = version.split(",")
            version_start = versArr[0]
            version_end = versArr[1]
        score = 9.0
        severity = p["severity"]
        attackComplexity = severity
        if p["severity"] == "LOW":
            score = 2.0
            attackComplexity = "HIGH"
            vectorString = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
        elif p["severity"] == "MODERATE":
            score = 5.0
            severity = "MEDIUM"
            vectorString = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"
        elif p["severity"] == "HIGH":
            score = 7.5
            attackComplexity = "LOW"
            vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
        tdata = CVE_TPL % dict(
            cve_id=cve_id,
            cwe_id="UNKNOWN",
            assigner=assigner,
            references=json.dumps(references),
            description=cve["summary"],
            vectorString=vectorString,
            vendor=vendor.lower(),
            product=product.lower(),
            version=version,
            version_start=version_start,
            version_end=version_end,
            severity=severity,
            attackComplexity=attackComplexity,
            score=score,
            publishedDate=cve["publishedAt"],
            lastModifiedDate=cve["updatedAt"],
        )
        jsonldata.append(json.loads(tdata))

with jsonlines.open("ghsa-l.json", mode="w") as writer:
    writer.write_all(jsonldata)

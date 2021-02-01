import json
import jsonlines

import sys

with open(sys.argv[1], "r") as f:
    data = json.load(f)
    cves = data["cves"]
    bulk = [dict(val, id=key) for key, val in cves.items() if key]

    with jsonlines.open("via4-l.json", mode="w") as writer:
        writer.write_all(bulk)

import json,pathlib,resource,xml.etree.ElementTree as ET
assert resource.getrlimit(resource.RLIMIT_AS)==(134217728,134217728)
root=pathlib.Path("/home/user/pr2974-recovery/windows/reader-60619956")
xml=ET.fromstring((root/"raw/controls.xml").read_bytes())
result=[]
for case in xml.findall(".//testcase"):
    if not case.attrib["classname"].endswith("test_windows_replaceable_reader_process"): continue
    props={}
    for row in case.findall("./properties/property"):
        assert row.attrib["name"] not in props
        props[row.attrib["name"]]=row.attrib["value"]
    values={key:json.loads(value) if key.endswith("_report") or key.startswith("child_capture_") else value for key,value in props.items()}
    result.append({"name":case.attrib["name"],"seconds":case.attrib.get("time"),"failure":case.find("failure") is not None,"properties":values})
(root/"windows-cases.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
print(json.dumps({"writers":result[:4],"audit_count":len(result)-4,"audits_passed":sum(not row["failure"] for row in result[4:]),"audit_original_candidate_equal":all(row["properties"].get("original_report")==row["properties"].get("candidate_report") for row in result[4:])}))

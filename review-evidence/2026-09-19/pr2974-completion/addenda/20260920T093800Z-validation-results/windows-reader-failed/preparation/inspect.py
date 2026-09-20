import json,pathlib,resource,xml.etree.ElementTree as ET
assert resource.getrlimit(resource.RLIMIT_AS)==(134217728,134217728)
root=pathlib.Path("/home/user/pr2974-recovery/windows/reader-60619956/raw")
types=(root/"types.stdout").read_bytes().decode()
xml=ET.fromstring((root/"controls.xml").read_bytes())
cases=xml.findall(".//testcase")
summary={"static":json.loads((root/"static-result.json").read_bytes()),"process":json.loads((root/"process-result.json").read_bytes()),
"binding":json.loads((root/"binding-comparison.json").read_bytes()),"case_count":len(cases),"failed":[{"name":case.attrib["name"],"class":case.attrib["classname"],"kind":child.tag,"message":child.attrib.get("message","")} for case in cases for child in case if child.tag in ("failure","error","skipped")],
"type_errors":[line for line in types.splitlines() if "error:" in line],"type_tail":types.splitlines()[-4:],
"controls_stdout":(root/"controls.stdout").read_bytes().decode()}
print(json.dumps(summary))

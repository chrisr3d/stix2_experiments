#!/usr/bin/env python3

import sys, json, os, time, datetime, re
from stix2 import *
from mixbox import idgen
from cybox.utils import Namespace

namespace = ['https://github.com/MISP/MISP', 'MISP']

not_implemented_attributes = ['yara', 'pattern-in-traffic', 'pattern-in-memory']	

non_indicator_attributes = ['text', 'comment', 'other', 'link', 'target-user', 'target-email', 
                            'target-machine', 'target-org', 'target-location', 'target-external', 
                            'email-target', 'vulnerability', 'attachment']

def loadEvent(args, pathname):
    try:
        filename = args[1]
        print(filename)
        tempFile = open(filename, 'r')
        events = json.loads(tempFile.read())
        return events
    except:
        print(json.dumps({'success' : 0, 'message' : 'The temporary MISP export file could not be read'}))
        sys.exit(1)
        
# converts timestamp to the format used by STIX
def getDateFromTimestamp(timestamp):
    return datetime.datetime.utcfromtimestamp(timestamp).isoformat() + "+00:00"

def setIdentity(event):
    org = event["Org"]
    identity = Identity(type="identity", id="identity--{}".format(org["uuid"]),
                        name=org["name"], identity_class="organization")
    return identity

def eventReport(event, identity):
    timestamp = getDateFromTimestamp(int(event["publish_timestamp"]))
    name = event["info"]
    report = Report(type="report", id="report--{}".format(event["uuid"]), created_by_ref=identity["id"],
                    name=name, published=timestamp, labels=["indicators"])
    return report

def generateEventPackage(event, SDOs):
    bundle_id = event['uuid']
    bundle = Bundle(type="bundle", spec_version="2.0", id="bundle--{}".format(bundle_id), objects=SDOs)
    return bundle

def main(args):
    pathname = os.path.dirname(sys.argv[0])
    if len(sys.argv) > 3:
        namespace[0] = sys.argv[3]
    if len(sys.argv) > 4:
        namespace[1] = sys.argv[4].replace(" ", "_")
        namespace[1] = re.sub('[\W]+', '', namespace[1])
    try:
        idgen.set_id_namespace({namespace[0]: namespace[1]})
    except ValueError:
        try:
            idgen.set_id_namespace(Namespace(namespace[0], namespace[1]))
        except TypeError:
            idgen.set_id_namespace(Namespace(namespace[0], namespace[1], "MISP"))
    event = loadEvent(args, pathname)
    event = event['response'][0]['Event']
    SDOs = []
    object_refs = []
    identity = setIdentity(event)
    SDOs.append(identity)
    report = eventReport(event, identity)
    SDOs.append(report)
    stix_package = generateEventPackage(event, SDOs)
    print(stix_package)

if __name__ == "__main__":
    main(sys.argv)
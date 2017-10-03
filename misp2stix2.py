#!/usr/bin/env python3

import sys, json, os, time, datetime, re
from stix2 import *
from mixbox import idgen
from cybox.utils import Namespace

namespace = ['https://github.com/MISP/MISP', 'MISP']

not_implemented_attributes = ['yara', 'pattern-in-traffic', 'pattern-in-memory']	

non_indicator_attributes = ['text', 'comment', 'other', 'link', 'target-user', 'target-email', 
                            'target-machine', 'target-org', 'target-location', 'target-external', 
                            'vulnerability', 'attachment']

def loadEvent(args, pathname):
    try:
        filename = args[1]
        tempFile = open(filename, 'r')
        events = json.loads(tempFile.read())
        return events
    except:
        print(json.dumps({'success' : 0, 'message' : 'The temporary MISP export file could not be read'}))
        sys.exit(1)
        
def saveFile(args, pathname, package):
    
#    try:
    tab_args = args[1].split('.')
    filename = "{}/tmp/misp.stix.{}{}.{}".format(pathname, tab_args[-4], tab_args[-3], tab_args[-1])
    print(package)
    d = os.path.dirname(filename)
    if not os.path.exists(d):
        os.makedirs(d)
    with open(filename, 'w') as f:
        f.write('{"package": ' + str(package) + '}')
#    except:
#        print(json.dumps({'success' : 0, 'message' : 'The STIX file could not be written'}))
#        sys.exit(1)
        
# converts timestamp to the format used by STIX
def getDateFromTimestamp(timestamp):
    return datetime.datetime.utcfromtimestamp(timestamp).isoformat() + "+00:00"

def setIdentity(event):
    org = event["Org"]
    identity = Identity(type="identity", id="identity--{}".format(org["uuid"]),
                        name=org["name"], identity_class="organization")
    return identity

def readAttributes(event, object_refs, identity):
    attributes = []
    for attribute in event["Attribute"]:
        if attribute["type"] in non_indicator_attributes:
            handleNonIndicatorAttribute(event, object_refs, attributes, attribute, identity)
        else:
            handleIndicatorAttribute(event, object_refs, attributes, attribute, identity)
    if event['Galaxy']:
        galaxies = event['Galaxy']
        for galaxy in galaxies:
            galaxyType = galaxy['type']
            if 'ware' in galaxyType:
                addMalware(object_refs, attributes, galaxy, identity)
            elif 'intrusion' in galaxyType:
                addIntrusionSet(object_refs, attributes, galaxy, identity)
            elif 'exploit' in galaxyType:
                addCampaign(object_refs, attributes, galaxy, identity)
            elif 'threat-actor' in galaxyType:
                addThreatActor(object_refs, attributes, galaxy, identity)
            elif 'rat' in galaxyType or 'tool' in galaxyType:
                addTool(object_refs, attributes, galaxy, identity)
        
    return attributes

def addAttackPattern(object_refs, attributes, galaxy, identity):
    attack_id = "attack-pattern--{}".format(galaxy['uuid'])
    attackPattern = AttackPattern()
    attributes.append(attackPattern)
    object_refs.append(attack_id)

def addCampaign(object_refs, attributes, galaxy, identity):
    campaign_id = "campaign--{}".format(galaxy['uuid'])
    campaign_args = {}
    campaign = Campaign(**campaign_args)
    attributes.append(campaign)
    object_refs.append(campaign_id)

def addCourseOfAction(object_refs, attributes, galaxy, identity):
    courseOfAction_id = "course-of-action--{}".format(galaxy['uuid'])
    courseOfAction = CourseOfAction()
    attributes.append(courseOfAction)
    object_refs.append(courseOfAction_id)
    
def addIntrusionSet(object_refs, attributes, galaxy, identity):
    intrusionSet_id = "intrusion-set--{}".format(galaxy['uuid'])
    name = galaxy['GalaxyCluster'][0]['value']
    intrusion_args = {'id': intrusionSet_id, 'type': 'intrusion-set', 'name': name}
    intrusionSet = IntrusionSet(**intrusion_args)
    attributes.append(intrusionSet)
    object_refs.append(intrusionSet_id)

def addMalware(object_refs, attributes, galaxy, identity):
    malware_id = "malware--{}".format(galaxy['uuid'])
    malware_args = {}
    malware = Malware(**malware_args)
    attributes.append(malware)
    object_refs.append(malware_id)

def addObservedData(object_refs, attributes, attribute, identity):
    observedData_id = "observed-data--{}".format(attribute['uuid'])
    timestamp = getDateFromTimestamp(int(attribute['timestamp']))
    if attribute['type'] == 'attachment':
        datatype = 'file'
    objects = {'0': {'type': datatype, "name": attribute['value']}}
    observedData_args = {'id': observedData_id, 'type': 'observed-data', 'number_observed': 1,
                         'first_observed': timestamp, 'last_observed': timestamp, 'objects': objects}
    observedData = ObservedData(**observedData_args)
    attributes.append(observedData)
    object_refs.append(observedData_id)

def addThreatActor(object_refs, attributes, galaxy, identity):
    threatActor_id = "threat-actor--{}".format(galaxy['uuid'])
    threatActor_args = {}
    threatActor = ThreatActor(**threatActor_args)
    attributes.append(threatActor)
    object_refs.append(threatActor_id)

def addTool(object_refs, attributes, galaxy, identity):
    tool_id = "tool--{}".format(galaxy['uuid'])
    tool_args = {}
    tool = Tool(**tool_args)
    attributes.append(tool)
    object_refs.append(tool_id)

def addVulnerability(object_refs, attributes, attribute, identity):
    vuln_id = "vulnerability--{}".format(attribute['uuid'])
    name = attribute['value']
    ext_refs = [{'source_name': 'cve',
                 'external_id': name}]
    vulnerability = Vulnerability(type='vulnerability', id=vuln_id, external_references=ext_refs)
    attributes.append(vulnerability)
    object_refs.append(vuln_id)
    
def handleNonIndicatorAttribute(event, object_refs, attributes, attribute, identity):
    attr_type = attribute['type']
    if attr_type == "vulnerability":
        addVulnerability(object_refs, attributes, attribute, identity)
    elif "target" in attr_type or attr_type == "attachment":
        addObservedData(object_refs, attributes, attribute, identity)

def handleIndicatorAttribute(event, object_refs, attributes, attribute, identity):
    indic_id = "indicator--{}".format(attribute['uuid'])
    category = attribute['category']
    killchain = [{'kill_chain_name': 'misp-category',
                 'phase_name': category}]
    args_indicator = {'valid_from': getDateFromTimestamp(int(attribute['timestamp'])), 'type': 'indicator',
                      'labels': ['malicious activity'], 'pattern': definePattern(attribute), 'id': indic_id,
                      'created_by_ref': identity}
    args_indicator['kill_chain_phases'] = killchain
    indicator = Indicator(**args_indicator)
#    indicator = Indicator(valid_from=getDateFromTimestamp(int(attribute["timestamp"])), type='indicator',
#                          labels=['malicious activity'], pattern="{}".format(definePattern(attribute)),
#                          id=indic_id, kill_chain_phases=killchain, created_by_ref=identity)
#    indicator.id = indic_id
#    indicator.labels = ['malicious activity']
#    indicator.pattern = "{}".format(definePattern(attribute))
    attributes.append(indicator)
    object_refs.append(indic_id)
    
def buildRelationships():
    return
    
def definePattern(attribute):
    attr_type = attribute['type']
    pattern =""
    if 'md5' in attr_type or 'sha' in attr_type:
        pattern += 'file:hashes.{} = \'{}\''.format(attr_type, attribute['value'])
    return [pattern]

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
#    print(event['Galaxy'])
#    sys.exit(0)
    SDOs = []
    object_refs = []
    identity = setIdentity(event)
    SDOs.append(identity)
    attributes = readAttributes(event, object_refs, identity)
    report = eventReport(event, identity)
    SDOs.append(report)
    for attribute in attributes:
        SDOs.append(attribute)
    stix_package = generateEventPackage(event, SDOs)
    saveFile(args, pathname, stix_package)
#    print(stix_package)

if __name__ == "__main__":
    main(sys.argv)
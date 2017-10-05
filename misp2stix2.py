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
            handleNonIndicatorAttribute(object_refs, attributes, attribute, identity)
        else:
            if attribute['to_ids'] == 'false':
                handleIndicatorAttribute(object_refs, attributes, attribute, identity)
            else:
                addObservedData(object_refs, attributes, attribute, identity)
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
    cluster = galaxy['GalaxyCluster'][0]
    campaign_id = "campaign--{}".format(cluster['uuid'])
    name = cluster['value']
    description = cluster['description']
    campaign_args = {'id': campaign_id, 'type': 'campaign', 'name': name, 'description': description,
                     'created_by_ref': identity}
    meta = cluster['meta']
    addAliases(meta, campaign_args)
    campaign = Campaign(**campaign_args)
    attributes.append(campaign)
    object_refs.append(campaign_id)

def addCourseOfAction(object_refs, attributes, galaxy, identity):
    courseOfAction_id = "course-of-action--{}".format(galaxy['uuid'])
    courseOfAction = CourseOfAction()
    attributes.append(courseOfAction)
    object_refs.append(courseOfAction_id)
    
def addIntrusionSet(object_refs, attributes, galaxy, identity):
    cluster = galaxy['GalaxyCluster'][0]
    intrusionSet_id = "intrusion-set--{}".format(cluster['uuid'])
    name = cluster['value']
    description = cluster['description']
    intrusion_args = {'id': intrusionSet_id, 'type': 'intrusion-set', 'name': name, 'description': description,
                      'created_by_ref': identity}
    meta = cluster['meta']
    addAliases(meta, intrusion_args)
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
    object0 = defineObservableType(attribute['type'], attribute['value'])
    # OBSERVABLE TYPES ARE CRAP
    objects = {'0': object0}
    observedData_args = {'id': observedData_id, 'type': 'observed-data', 'number_observed': 1,
                         'first_observed': timestamp, 'last_observed': timestamp, 'objects': objects,
                         'created_by_ref': identity}
    observedData = ObservedData(**observedData_args)
    attributes.append(observedData)
    object_refs.append(observedData_id)

def addThreatActor(object_refs, attributes, galaxy, identity):
    cluster = galaxy['GalaxyCluster'][0]
    threatActor_id = "threat-actor--{}".format(cluster['uuid'])
    name = cluster['value']
    description = cluster['description']
    labels = ['crime-syndicate'] # Arbitrary value as a first test
    threatActor_args = {'id': threatActor_id, 'type': 'threat-actor', 'name': name, 'description': description,
                        'labels': labels, 'created_by_ref': identity}
    meta = cluster['meta']
    addAliases(meta, threatActor_args)
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
    vuln_args = {'type': 'vulnerability', 'id': vuln_id, 'external_references': ext_refs, 'name': name,
                 'created_by_ref': identity}
    vulnerability = Vulnerability(**vuln_args)
    attributes.append(vulnerability)
    object_refs.append(vuln_id)
    
def addAliases(meta, argument):
    if meta['synonyms']:
        aliases = []
        for a in meta['synonyms']:
            aliases.append(a)
        argument['aliases'] = aliases
        
def defineObservableType(dtype, val):
    object0 = {}
#    if dtype == '':
#        datatype = 'artifact'
#    elif dtype == '':
#        datatype = 'autonomous-system'
#    elif dtype == '':
#        datatype = 'directory'
#    elif dtype == '':
#        datatype = 'domain-name'
#    el
    if 'email' in dtype and 'name' not in dtype and ('src' in dtype or 'dst' in dtype or 'target' in dtype):
        object0['type'] = 'email-address'
        object0['value'] = val
    elif 'email' in dtype and ('body' in dtype or 'subject' in dtype or 'header' in dtype or 'reply' in dtype):
        object0['type'] = 'email-message'
        object0['subject'] = val
        object0['is_multipart'] = 'false'
    elif 'attachment' in dtype:
        object0['type'] = 'file'
        object0['name'] = val
#    elif dtype == '':
#        datatype = 'ipv4-addr'
#    elif dtype == '':
#        datatype = 'ipv6-addr'
#    elif dtype == '':
#        datatype = 'mac-addr'
#    elif dtype == 'mutex':
#        datatype = 'mutex'
#    elif dtype == '':
#        datatype = 'network-traffic'
#    elif dtype == '':
#        datatype = 'process'
#    elif dtype == '':
#        datatype = 'software'
    elif dtype == 'url':
        object0['type'] = 'url'
        object0['value'] = val
#    elif dtype == '':
#        datatype = 'user-account'
    elif 'regkey' in dtype:
        object0['type'] = 'windows-registry-key'
        object0['key'] = val
    elif 'x509' in dtype:
        object0['type'] = 'x509-certificate'
    elif 'md5' in dtype or 'sha' in dtype:
        object0['type'] = 'file'
        object0['hashes'] = {dtype: val}
    else:
        object0['type'] = 'file' # CRAP BEFORE FINDING HOW TO HANDLE ALL THE CASES \o/
        object0['name'] = val
    return object0
    
def handleNonIndicatorAttribute(object_refs, attributes, attribute, identity):
    attr_type = attribute['type']
    if attr_type == "vulnerability":
        addVulnerability(object_refs, attributes, attribute, identity)
#    elif "target" in attr_type or attr_type == "attachment":
    else:
        addObservedData(object_refs, attributes, attribute, identity)

def handleIndicatorAttribute(object_refs, attributes, attribute, identity):
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

def eventReport(event, object_refs, identity):
    timestamp = getDateFromTimestamp(int(event["publish_timestamp"]))
    name = event["info"]
    report = Report(type="report", id="report--{}".format(event["uuid"]), created_by_ref=identity["id"],
                    name=name, published=timestamp, labels=["indicators"], object_refs=object_refs)
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
    report = eventReport(event, object_refs, identity)
    SDOs.append(report)
    for attribute in attributes:
        SDOs.append(attribute)
    stix_package = generateEventPackage(event, SDOs)
    saveFile(args, pathname, stix_package)
#    print(stix_package)

if __name__ == "__main__":
    main(sys.argv)

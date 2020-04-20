import os
import json
import urllib.request as request
import sys
from pymisp import ExpandedPyMISP, MISPEvent, MISPOrganisation

# REMARKS:
# - The Event uuids and names are preserved. Hopefully MISP won't create duplicated events with multiple fetches
# - Attribute uuids change each run. Hopefully MISP will ignore duplicates
# - Each update a new manifest and hashes file is created
# - If the feed is remote you should have a webserver on the outputdir (ex: nginx)

# Change this vars to reflect your structure
# Output dir must exist
outputdir="<your_feed_path>"
# URL for Brazilian CIDR blocks per ASN. file format: ASN|ORG|CNPJ|CIDR1|CIDR2|...
url="ftp://ftp.registro.br/pub/numeracao/origin/nicbr-asn-blk-latest.txt"
# The name and uuid of the org for the created events. It should exist on your misp instance
org_uuid="<your_org_uuid>"
org_name="<your_org_name>"

# ---- Functions
def saveEvent(event):
# Saves an event to disk with name <uuid>.json
    try:
        with open(os.path.join(outputdir, f'{event["Event"]["uuid"]}.json'), 'w') as f:
            json.dump(event, f, indent=2)
            f.close()
    except Exception as e:
        print(e)
        sys.exit('Could not create the event dump.')

def saveHashes(hashes):
# Creates the hashes.csv file with all the hashes for the events
    try:
        with open(os.path.join(outputdir, 'hashes.csv'), 'w') as hashFile:
            for element in hashes:
                hashFile.write('{},{}\n'.format(element[0], element[1]))
    except Exception as e:
        print(e)
        sys.exit('Could not create the quick hash lookup file.')

def saveManifest(manifest):
# Saves the manifest file
    try:
        manifestFile = open(os.path.join(outputdir, 'manifest.json'), 'w')
        manifestFile.write(json.dumps(manifest))
        manifestFile.close()
    except Exception as e:
        print(e)
        sys.exit('Could not create the manifest file.')

def get_events_from_manifest():
# Loads the manifest.json file and creates a dict indexed by uuid
    try:
        manifest_path = os.path.join(outputdir, 'manifest.json')
        with open(manifest_path, 'r') as f:
            man = json.load(f)
            for event_uuid, event_json in man.items():
                manifest[event_uuid] = event_json
            return manifest
    except FileNotFoundError as e:
        print('Manifest not found, generating a fresh one')
        return {}

def find_event(manifest, name):
# Returns the uuid of an event with particular INFO field
    for event_uuid in manifest:
        if manifest[event_uuid]['info'] == name:
            return event_uuid

# --- Main program
# Start with empty manifest
manifest={}
# Get URL and convert to str for iteration
req = request.Request(url)
with request.urlopen(req) as response:
        response = response.read()
f = response.decode().splitlines()

# Open current manifest or get empty one
old_manifest = get_events_from_manifest()

# We will recalculate all hashes again
hashes = []

for line in f:
    fields = line.split("|")
    ASN = fields.pop(0)
    ORG = fields.pop(0)
    CNPJ = fields.pop(0)
    EVENT_NAME = str(ORG+ " " + CNPJ)
    result_uuid = find_event(old_manifest, EVENT_NAME)
    if result_uuid : # if event exists, get from manifest
        event = MISPEvent()
        event.uuid = result_uuid
        event.from_dict(**old_manifest[result_uuid])
        print("Atualizando evento: "+event.uuid+" "+event.info)
    else:   # event does not exist, generate a new one
        event = MISPEvent()
        #event.id = len(old_manifest)+1
        event.info = str(ORG+ " " + CNPJ)
        event.analysis = 0
        event.threat_level_id = 1
        event.published = 0
        event.orgc = MISPOrganisation()
        event.orgc.uuid = org_uuid
        event.orgc.name = org_name
        print("CRIANDO NOVO EVENTO: "+event.uuid+" "+event.info)
    event.add_attribute("AS",str(ASN)) # Add AS Number to Event
    for field in fields:  # Add CIDR blocks
        event.add_attribute("ip-dst",str(field))
    e_feed = event.to_feed(with_meta=True)
    hashes += [[h, event.uuid] for h in e_feed['Event'].pop('_hashes')]
    manifest.update(e_feed['Event'].pop('_manifest'))
    saveEvent(e_feed)
saveManifest(manifest)
saveHashes(hashes)

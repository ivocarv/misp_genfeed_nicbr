import os
import json
import urllib.request as request
import shutil
import sys
from pymisp import ExpandedPyMISP, MISPEvent, MISPOrganisation

# change this vars
outputdir="/home/srcc/code/brasil_ips/misp_feed/"
#file format: ASN|ORG|CNPJ|CIDR1|CIDR2|...
url="ftp://ftp.registro.br/pub/numeracao/origin/nicbr-asn-blk-latest.txt"
org_uuid="PUT-DESIRED-UUID-HERE"
org_name="YOUR-ORG-NAME"

# ---- Functions
def saveEvent(event):
    try:
        with open(os.path.join(outputdir, f'{event["Event"]["uuid"]}.json'), 'w') as f:
            json.dump(event, f, indent=2)
            f.close()
    except Exception as e:
        print(e)
        sys.exit('Could not create the event dump.')

def saveHashes(hashes):
    try:
        with open(os.path.join(outputdir, 'hashes.csv'), 'w') as hashFile:
            for element in hashes:
                hashFile.write('{},{}\n'.format(element[0], element[1]))
    except Exception as e:
        print(e)
        sys.exit('Could not create the quick hash lookup file.')

def saveManifest(manifest):
    try:
        manifestFile = open(os.path.join(outputdir, 'manifest.json'), 'w')
        manifestFile.write(json.dumps(manifest))
        manifestFile.close()
    except Exception as e:
        print(e)
        sys.exit('Could not create the manifest file.')

# --- Main program
# Get URL and convert to str for iteration
req = request.Request(url)
with request.urlopen(req) as response:
        response = response.read()
f = response.decode().splitlines()

# erase target dir and recreate
try:
    shutil.rmtree(outputdir)
except Exception as e:
    print(e)
os.mkdir(outputdir)

manifest = {}
hashes = []
counter = 1

for line in f:
        print (line)
        fields = line.split("|")
        ASN = fields.pop(0)
        ORG = fields.pop(0)
        CNPJ = fields.pop(0)
        event = MISPEvent()
        event.id = len(manifest)+1
        event.info = str(ORG+ " " + CNPJ)
        event.analysis = 0
        event.threat_level_id = 1
        event.published = 0
        event.orgc = MISPOrganisation()
        event.orgc.uuid = org_uuid
        event.orgc.name = org_name
        event.add_attribute("AS",str(ASN))
        #event.date = today
        for field in fields:
                event.add_attribute("ip-dst",str(field))
        e_feed = event.to_feed(with_meta=True)
        hashes += [[h, event.uuid] for h in e_feed['Event'].pop('_hashes')]
        manifest.update(e_feed['Event'].pop('_manifest'))
        saveEvent(e_feed)
        counter +=1
saveManifest(manifest)
saveHashes(hashes)

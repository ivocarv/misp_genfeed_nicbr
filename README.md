# misp_genfeed_nicbr

Script to generate a feed from all Brazilian IP's separated by AS. Each event info is the orgname and CNPJ for quick overlook on correlations. 
Downloads CIDR blocks and ASN from ftp://ftp.registro.br/pub/numeracao/origin/nicbr-asn-blk-latest.txt

New AS's will create new events and new CIDR blocks will update existing events.

Requires:
* json
* urllib
* pymisp

You can import feed locally or use a webserver for network feed.

#!/bin/sh -ex

DEST=-
DEST=/dev/null

curl -s 'http://127.0.0.1:6544/matatabi.json?source=mawilab' > ${DEST}
# not supported yet
#curl -s 'http://127.0.0.1:6544/matatabi.json?source=sflow_dixie' > ${DEST}
curl -s 'http://127.0.0.1:6544/matatabi.json?source=zeus_dga_netflow' > ${DEST}
curl -s 'http://127.0.0.1:6544/matatabi.json?source=ntpamplifiers_sflow_dixie' > ${DEST}
curl -s 'http://127.0.0.1:6544/matatabi.json?source=suspiciousheavyhitters_sflow_dixie' > ${DEST}
curl -s 'http://127.0.0.1:6544/matatabi.json?source=phish_summary' > ${DEST}
#curl -s 'http://127.0.0.1:6544/matatabi.json?source=mawi_pcaps' > ${DEST}
#curl -s 'http://127.0.0.1:6544/matatabi.json?source=dns_pcaps' > ${DEST}
#curl -s 'http://127.0.0.1:6544/matatabi.json?source=netflow_wide' > ${DEST}
curl -s 'http://127.0.0.1:6544/matatabi.json?source=spam' > ${DEST}



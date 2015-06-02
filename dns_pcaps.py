from n6sdk.data_spec.fields import *
from necoma.common import *
from datetime import datetime

class DnsPcapsDataBackendApi(object):
    @staticmethod
    def parse(auth_data, params, query_result, **kwargs):
        for data in query_result:
            if data[2].find('.') > 1 or data[4].find('.') > 1:
                key = 'ip'
            else:
                key = 'ipv6'

            if data[2] == '' and key == 'ip':
                data[2] = '0.0.0.0'
            if data[4] == '' and key == 'ip':
                data[4] = '0.0.0.0'
            if data[2] == '' and key == 'ipv6':
                data[2] = '::'
            if data[4] == '' and key == 'ipv6':
                data[4] = '::'

            yield {
                'category': 'dns-query',
                'time': datetime.utcfromtimestamp(data[0]),
                'proto': data[1],
                'address': [{key: data[2], 'dir': 'src'}, {key: data[4], 'dir': 'dst'}],
                'sport': data[3],
                'dport': data[5],
                'len': data[6],
                'ttl': data[7],
                'fqdn': data[12],
                'confidence': 'medium',
                }


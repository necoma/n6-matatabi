from n6sdk.data_spec.fields import *
from datetime import datetime

class NetflowWideDataBackendApi(object):
    @staticmethod
    def parse(auth_data, params, query_result, **kwargs):
        for data in query_result:
            if data[3].find('.') > 1 or data[4].find('.') > 1:
                key = 'ip'
            else:
                key = 'ipv6'

            if data[3] == '' and key == 'ip':
                data[3] = '0.0.0.0'
            if data[4] == '' and key == 'ip':
                data[4] = '0.0.0.0'
            if data[3] == '' and key == 'ipv6':
                data[3] = '::'
            if data[4] == '' and key == 'ipv6':
                data[4] = '::'

            yield {
                'category': 'flow',
                'name': 'zeus',
                'time': datetime.utcfromtimestamp(data[0]),
                'until': datetime.utcfromtimestamp(data[1]),
                'address': [{'ip': data[3], 'dir': 'src'}, {'ip': data[4], 'dir': 'dst'}],
                'sport': data[5],
                'dport': data[6],
                'proto': data[7].lower(),
                }


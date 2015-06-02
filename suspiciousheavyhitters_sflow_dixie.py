from n6sdk.data_spec.fields import *
from necoma.common import *
from datetime import datetime

class HeavyHittersSflowDataBackendApi(object):
    @staticmethod
    def parse(auth_data, params, query_result, **kwargs):
        for data in query_result:
            src = {}
            dst = {}
            if data[0] is not None and data[0] != '':
                src = {('ip' if is_ipv4(data[0]) else 'ipv6'): data[0],  'dir': 'src'}
            if data[1] is not None and data[1] != '':
                dst = {('ip' if is_ipv4(data[1]) else 'ipv6'): data[1],  'dir': 'dst'}
            yield {
                'category': 'flow-anomaly',
                'address': [src if src != {} else {'dir': 'src'} , dst if dst != {} else {'dir': 'dst'}],
                'byte': data[2],
                'pkt': data[3],
                'confidence': convert_conf(data[4]),
                'time': datetime.strptime(data[5], "%Y%m%d"),
                'until': datetime.strptime(data[5], "%Y%m%d"),
                }


from n6sdk.data_spec.fields import *
from datetime import datetime

class SflowDataBackendApi(object):
    @staticmethod
    def parse(auth_data, params, query_result, **kwargs):
        for data in query_result:
            if data[0] is None or data[0] == '':
                continue
            if data[1] is None or data[1] == '':
                continue
            if data[2] is None or data[2] == '':
                continue
            if data[3] is None or data[3] == '':
                continue
            print data
            yield {
                'category': 'flow',
                'address': [{'ip': data[0], 'dir': 'src'}, {'ip': data[2], 'dir': 'dst'}],
                'sport': data[1],
                'dport': data[3],
                'name': data[4],
                'nbdetector': data[5],
                'confidence': data[6],
                'time': datetime.strptime(data[7], "%Y%m%d"),
                'until': datetime.strptime(data[7], "%Y%m%d"),
                }


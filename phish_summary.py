from n6sdk.data_spec.fields import *
from necoma.common import *
from datetime import datetime

class PhishSummaryDataBackendApi(object):
    @staticmethod
    def parse(auth_data, params, query_result, **kwargs):
        for data in query_result:
            try:
                datetime.utcfromtimestamp(data[4]),
            except:
                continue

            if data[5] == '':
                continue
            if data[6] == '':
                data[6] = 3939 #XXX
            if data[2] == None:
                data[2] = -1 #XXX
            yield {
                'category': 'phish',
                #'id': data[0],
                #'type': data[1],
                'confidence': 'medium',
                'siteid': data[2],
                'sitecode': data[3],
                'time': datetime.utcfromtimestamp(data[4]),
                'address': [{'ip': data[5], 'dir': 'src', 'asn': str(data[6]).replace('_', '.')}],
                'fqdn': data[7],
                'domain': data[8],
                'url': data[9][1:2048],
                }


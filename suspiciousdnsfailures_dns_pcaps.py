from n6sdk.data_spec.fields import *
from necoma.common import *
from datetime import datetime

class DnsFailuerPcapsDataBackendApi(object):
    @staticmethod
    def parse(auth_data, params, query_result, **kwargs):
        for data in query_result:
            yield {
                'category': 'other',
                'fqdn': data[0],
                'address': [{'ip': data[1], 'dir': 'src'}],
                'clusterid': data[2],
                'clustersize': data[3],
                'degree': data[4],
                'confidence': convert_conf(data[5]),
                'time': datetime.strptime(data[6], "%Y%m%d"),
                'until': datetime.strptime(data[6], "%Y%m%d"),
                }


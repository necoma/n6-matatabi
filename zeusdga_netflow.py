from n6sdk.data_spec.fields import *
from necoma.common import *
from datetime import datetime

class ZeusDGANetflowDataBackendApi(object):
    @staticmethod
    def parse(auth_data, params, query_result, **kwargs):
        for data in query_result:
            if is_fqdn(data[3]) is True:
                continue

            yield {
                'category': 'bots',
                'name': 'zeus',
                'time': datetime.utcfromtimestamp(data[0]),
                'until': datetime.utcfromtimestamp(data[1]),
                'address': [{('ip' if is_ipv4(data[3]) else 'ipv6'): data[3],  'dir': 'src'},
			    {('ip' if is_ipv4(data[4]) else 'ipv6'): data[4],  'dir': 'dst'}],
                'sport': data[5],
                'dport': data[6],
                'proto': data[7].lower(),
                }


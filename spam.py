from necoma.common import *
from n6sdk.data_spec.fields import *
from datetime import datetime

class SpamDataBackendApi(object):
    @staticmethod
    def parse(auth_data, params, query_result, **kwargs):
        for data in query_result:
            if data[0] is None or data[0] == '':
                continue
            if data[1] is None or data[1] == '':
                continue
            if data[2] is None or data[2] == '':
                continue
            if is_fqdn(data[1]) is True:
                continue
            if data[1] is not None and data[1] != '':
               data[1] = data[1].replace('IPv6:', '')

            yield {
                'category': 'other',
                'time': datetime.utcfromtimestamp(data[0]),
                'address': [{('ip' if is_ipv4(data[1]) else 'ipv6'): data[1], 'rdns': data[3], 'dir': 'src'}],
                'fqdn': 'not.supported.yet',
                #'fqdn': data[2],
                }


from n6sdk.data_spec.fields import *
from necoma.common import *
from datetime import datetime

class NtpampSflowDataBackendApi(object):
    @staticmethod
    def parse(auth_data, params, query_result, **kwargs):
        for data in query_result:

            columns = {'address':0, 'byte':1, 'pkt':2, 'time.min':4, 'time.max':4, 'confidence':6}
            skip = False
            for key, value in params.items():
                if key == 'source':
                    continue
                if key == 'time.min' or key == 'time.max':
                    continue

                if params[key][0] != data[columns[key]]:
                    skip = True
                    break

            if skip is True:
                continue

            yield {
                'source': params['source'][0],
                'category': 'dos-attacker',
                'proto': 'udp',
                'address': [{'ip': data[0], 'dir': 'src'}],
                'sport': 123,
                'byte': data[1],
                'pkt': data[2],
                'confidence': convert_conf(data[3]),
                'time': datetime.strptime(data[4], "%Y%m%d"),
                'until': datetime.strptime(data[4], "%Y%m%d"),
                }


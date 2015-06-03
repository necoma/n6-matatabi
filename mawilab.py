from n6sdk.data_spec.fields import *
from necoma.common import *
from datetime import datetime

#class MawilabDataSpec(DataSpec):
#    id = None
#    restriction = None
#
#    category = Ext(
#        enum_values=DataSpec.category.enum_values + ('flow-anomaly',),
#    )
#
#    address = ExtendedAddressField(in_params='optional',in_result='required')
#    nbdetector = IntegerField(in_params='optional', in_result='required')
#    source = UnicodeField(in_params='optional', in_result=None)

class MawilabDataBackendApi(object):
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

            columns = {'sport':1, 'dport':3, 'name':4, 'nbdetector':5, 'confidence':6}
            skip = False
            for key, value in params.items():
                if key == 'source':
                    continue
                if columns.has_key(key) is False:
                    continue

                if key == 'ip':
                    if (params[key][0] != data[0]) and (params[key][0] != data[2]):
                       skip = True
                       break
                    continue

                if params[key][0] != data[columns[key]]:
                    skip = True
                    break

            if skip is True:
                continue

            yield {
                'source': 'mawilab',
                'category': 'flow-anomaly',
                'address': [{'ip': data[0], 'dir': 'src'}, {'ip': data[2], 'dir': 'dst'}],
                'sport': data[1],
                'dport': data[3],
                'name': data[4],
                'nbdetector': data[5],
                'confidence': convert_conf(data[6]),
                'time': datetime.strptime(data[7], "%Y%m%d"),
                #'until': datetime.strptime(data[7], "%Y%m%d"),
                }


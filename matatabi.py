from necoma.common import *
from necoma.zeusdga_netflow import *
from necoma.sflow import *
from necoma.mawilab import *
from necoma.ntpamplifiers_sflow_dixie import *
from necoma.suspiciousheavyhitters_sflow_dixie import *
from necoma.suspiciousdnsfailures_dns_pcaps import *
from necoma.phish_summary import *
from necoma.mawi_pcaps import *
from necoma.dns_pcaps import *
from necoma.netflow_wide import *
from necoma.spam import *
from pyhive import presto
from n6sdk.data_spec import DataSpec, Ext
from n6sdk.class_helpers import singleton
from n6sdk.pyramid_commons import HttpResource
from n6sdk.data_spec.fields import *
from datetime import datetime, date, time, timedelta

class MatatabiDataSpec(DataSpec):
    id = None
    restriction = None

    category = Ext(
        enum_values=DataSpec.category.enum_values + ('flow-anomaly',),
    )


    address = ExtendedAddressField(in_params='optional',in_result='optional')
    nbdetector = IntegerField(in_params='optional', in_result='optional')
    byte = IntegerField(in_params='optional', in_result='optional')
    pkt = IntegerField(in_params='optional', in_result='optional')
    source = UnicodeField(in_params='optional', in_result='optional')
    confidence = UnicodeField(in_params='optional', in_result='optional')
    # for dns failure
    clusterid = IntegerField(in_params='optional', in_result='optional')
    clusterize= IntegerField(in_params='optional', in_result='optional')
    degree= UnicodeField(in_params='optional', in_result='optional')
    # for phish_summary
    siteid = IntegerField(in_params=None, in_result='optional')
    sitecode = IntegerField(in_params=None, in_result='optional')
    domain = UnicodeField(in_params=None, in_result='optional')
    # for mawi pcaps
    len = IntegerField(in_params=None, in_result='optional')
    ttl = IntegerField(in_params=None, in_result='optional')

class MatatabiHttpResource(HttpResource):
    def __init__(self, example_dummy_feature='foobar', **kwargs):
        super(MatatabiHttpResource, self).__init__(**kwargs)

@singleton
class MatatabiDataBackendApi(object):
    
    def __init__(self, settings):
        # STORAGE-SPECIFIC IMPLEMENTATION DETAILS:
        # (for our example JSON-file-based storage...)
        pass

    def RunQuery(self, query, parameters):
        cursor = presto.connect('localhost').cursor()
        try:
            cursor.execute(query, parameters)
        except presto.DatabaseError as e:
            raise
        res = cursor.fetchall()
        return res

    def select_records(self, auth_data, params, **kwargs):
        if auth_data != 'anonymous':
            raise AuthorizationError(public_message='Who is it?!')
        # this is a dummy and naive implementation :) -- in a real
        # implementation some kind of database query would need to
        # be performed instead...

        time_max = (datetime.utcnow() + timedelta(days=2)).strftime("%Y%m%d")
        time_min = '20130101'
        if 'time.max' in params.keys():
            time_max = params['time.max'][0].strftime("%Y%m%d")
        if 'time.min' in params.keys():
            time_min = params['time.min'][0].strftime("%Y%m%d")

        if time_max == '' and time_min == '':
            query = "select * from " + params['source'][0] + " order by dt" 
            parameters = None
        else:
            query = "select * from " + params['source'][0] + " where dt<=%s and dt>=%s order by dt" 
            parameters = (time_max, time_min)

        query_result = self.RunQuery(query, parameters)

        # table specific callbacks
        if params['source'][0] == 'mawilab':
            return MawilabDataBackendApi.parse(auth_data, params, query_result, **kwargs)
        elif params['source'][0] == 'sflow_dixie':
            return SflowDataBackendApi.parse(auth_data, params, query_result, **kwargs)
        elif params['source'][0] == 'zeus_dga_netflow':
            return ZeusDGANetflowDataBackendApi.parse(auth_data, params, query_result, **kwargs)
        elif params['source'][0] == 'ntpamplifiers_sflow_dixie':
            return NtpampSflowDataBackendApi.parse(auth_data, params, query_result, **kwargs)
        elif params['source'][0] == 'suspiciousheavyhitters_sflow_dixie':
            return HeavyHittersSflowDataBackendApi.parse(auth_data, params, query_result, **kwargs)
        elif params['source'][0] == 'phish_summary':
            return PhishSummaryDataBackendApi.parse(auth_data, params, query_result, **kwargs)
        elif params['source'][0] == 'mawi_pcaps':
            return MawiPcapsDataBackendApi.parse(auth_data, params, query_result, **kwargs)
        elif params['source'][0] == 'dns_pcaps':
            return DnsPcapsDataBackendApi.parse(auth_data, params, query_result, **kwargs)
        elif params['source'][0] == 'netflow_wide':
            return NetflowWideDataBackendApi.parse(auth_data, params, query_result, **kwargs)
        elif params['source'][0] == 'spam':
            return SpamDataBackendApi.parse(auth_data, params, query_result, **kwargs)
        else:
            print "no parser found"

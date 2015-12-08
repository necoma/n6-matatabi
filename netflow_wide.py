from n6sdk.data_spec.fields import *
from datetime import datetime, date, time, timedelta
from pyhive import presto


class NetflowWideDataBackendApi(object):
    @staticmethod
    def RunQuery(params, **kwargs):
	parameters = []
        time_max = (datetime.utcnow() + timedelta(days=2)).strftime("%Y%m%d")
        time_min = (datetime.utcnow() - timedelta(days=20)).strftime("%Y%m%d")
	ip = None
        if 'time.max' in params.keys():
            time_max = params['time.max'][0].strftime("%Y%m%d")
        if 'time.min' in params.keys():
            time_min = params['time.min'][0].strftime("%Y%m%d")
        if 'ip' in params.keys():
            ip = params['ip'][0]

	#query = "select * from " + params['source'][0] 
	query = "select * from " + "netflow_wide_rcfile"
        if time_max != '' or time_min != '' or ip is not None:
            query += " where "

        if time_max != '':
            query += " dt<=%s"
            parameters.append(time_max)
        if time_min != '':
            query += " and dt>=%s"
            parameters.append(time_min)
	if ip is not None:
            query += " and (sa = %s or da = %s)"
            parameters.append(ip)
            parameters.append(ip)

        query += "order by dt"
        cursor = presto.connect('localhost').cursor()
        try:
            cursor.execute(query, parameters)
        except presto.DatabaseError as e:
            raise
        res = cursor.fetchall()
        return res

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
                'category': 'other',
		'source':  params['source'][0],
                'time': datetime.utcfromtimestamp(data[0]),
                'until': datetime.utcfromtimestamp(data[1]),
                'address': [{'ip': data[3], 'dir': 'src'}, {'ip': data[4], 'dir': 'dst'}],
                'sport': data[5],
                'dport': data[6],
                'proto': data[7].lower(),
                }


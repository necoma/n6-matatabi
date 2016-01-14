from n6sdk.data_spec.fields import *
from datetime import datetime, date, time, timedelta
from pyhive import presto

class SflowDataBackendApi(object):
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
            ip = params['ip']

        query = "select srcip,dstip,ipprotocol,tcpsrcport,udpsrcport,tcpdstport,udpdstport,unixsecondsutc from " + params['source'][0] 

        if time_max != '' or time_min != '' or ip is not None:
            query += " where "

        if time_max != '':
            query += " dt<=%s"
            parameters.append(time_max)
        if time_min != '':
            query += " and dt>=%s"
            parameters.append(time_min)
        if ip is not None:
            query += " and (srcip = " + " or srcip = ".join(["%s" for i in ip]) + " or dstip = " + " or dstip = ".join(["%s" for i in ip]) + ")"
            print query
            for j in [1,2]:
                for i in ip:
                    parameters.append(i)

        query += " order by dt"
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
            #print data
            # protocol switch
            if data[2] is 1:
                proto='icmp'
                sport=0
                dport=0
            elif data[2] is 6:
                proto='tcp'
                sport=data[3]
                dport=data[5]
            elif data[2] is 17:
                proto='udp'
                sport=data[4]
                dport=data[6]
            else:
                continue

            yield {
                'category': 'flow',
                'address': [{'ip': data[0], 'dir': 'src'}, {'ip': data[1], 'dir': 'dst'}],
                'sport': sport,
                'dport': dport,
                'proto': proto,
                'source': params['source'][0],
                'time': datetime.utcfromtimestamp(data[7]),
                'until': datetime.utcfromtimestamp(data[7]),
                }


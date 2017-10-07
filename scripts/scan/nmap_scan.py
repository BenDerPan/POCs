from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from libnmap.reportjson import ReportEncoder,ReportDecoder
from time import sleep
import json
import logging

class NmapScaner(object):
    '''
    nmap端口扫描+应用识别实现
    '''
    @staticmethod
    def scan(targets,options='-O -sV'):
        '''
        执行扫描
        :param targets:扫描的目标，可以是List集合对象也，可以是以逗号分隔的目标集合。如"baidu.com" ，["baidu.com","qq.com"] ，"baidu.com,qq.com"
        :param options:扫描参数，同namp一致。
        :return:成功返回扫描结果Dict对象，否则返回None
        '''
        try:
            nmapProcess=NmapProcess(targets=targets,options=options)
            nmapProcess.run()
            results = NmapParser.parse_fromstring(nmapProcess.stdout)
            jsonData = json.loads(json.dumps(results, cls=ReportEncoder))
            return jsonData
        except Exception as e:
            logging.error("Nmap scan error:{}".format(e))
            return None

    @staticmethod
    def scan_background(targets,options='-O -sV'):
        '''
        后台执行扫描，带进度输出
        :param targets:扫描的目标，可以是List集合对象也，可以是以逗号分隔的目标集合。如"baidu.com" ，["baidu.com","qq.com"] ，"baidu.com,qq.com"
        :param options:扫描参数，同namp一致。
        :return:成功返回扫描结果Dict对象，否则返回None
        '''
        try:
            nmapProcess=NmapProcess(targets=targets,options=options)
            nmapProcess.run_background()
            while nmapProcess.is_running():
                print("[*]Nmap Scan running: ETC: {0} DONE: {1}%".format(nmapProcess.etc,nmapProcess.progress))
                sleep(1)
            results=NmapParser.parse_fromstring(nmapProcess.stdout)
            jsonData=json.loads(json.dumps(results,cls=ReportEncoder))
            return jsonData
        except Exception as e:
            logging.error("Nmap scan error:{}".format(e))
            return None

if __name__ == '__main__':
    result1=NmapScaner.scan("localhost")
    result2=NmapScaner.scan_background("localhost")
    print(json.dumps(result1,indent=4))
    print("*"*80)
    print(json.dumps(result2,indent=4))


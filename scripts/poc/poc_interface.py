from abc import ABCMeta,abstractclassmethod

class PocInterface(metaclass=ABCMeta):
    '''
    POC 实现接口
    '''
    @abstractclassmethod
    def validate(self,*args,**kwargs):
        '''
        漏洞验证接口方法
        :param args: 自定义参数
        :param kwargs: 自定义参数
        :return: 自定义，建议存在返回True,否则返回False
        '''
        pass

    @abstractclassmethod
    def exploit(self,*args,**kwargs):
        '''
        漏洞利用接口方法
        :param args: 自定义参数
        :param kwargs: 自定义参数
        :return: 自定义
        '''
        pass
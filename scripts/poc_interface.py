from abc import ABCMeta,abstractclassmethod

class PocInterface(metaclass=ABCMeta):
    '''
    POC Implements Interfaces
    '''
    @abstractclassmethod
    def validate(self,*args,**kwargs):
        pass

    @abstractclassmethod
    def exploit(self,*args,**kwargs):
        pass
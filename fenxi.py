#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : whisper
# @Site    : https://github.com/wei19960330
import os
import re

def fenxi(log):
    sql = r'product.php|preg_\w+|execute|echo|print|print_r|var_dump|(fp)open|^eval$|file_get_contents|include|require|require_once|shell_exec|phpinfo|system|passthru|\(?:define|base64_decode\(|group\s+by.+\(|%20or%20|%20and%20|sleep|delay|nvarchar|exec|union|^select$|version|insert|information_schema|chr\(|concat|%bf|sleep\((\s*)(\d*)(\s*)\)|current|having|database|%20select%20|%20and%201=1|%20and%201=2|%20exec|%27exec| information_schema.tables|%20information_schema.tables|%20where%20|%20union%20|%20SELECT%20|%2ctable_name%20|cmdshell|%20table_schema'

    xss = r'alert|^script$|<|>|%3E|%3c|&#x3E|\u003c|\u003e|&#x'

    sen = r'\.{2,}|%2e{2,}|%252e{2,}|%uff0e{2,}0x2e{2,}|\./|\{FILE\}|%00+|json|\.shtml|\.pl|\.sh|\.do|\.action|zabbix|phpinfo|/var/|/opt/|/local/|/etc|/apache/|\.log|invest\b|\.xml|apple-touch-icon-152x152|\.zip|\.rar|\.asp\b|\.php|\.bak|\.tar\.gz|\bphpmyadmin\b|admin|\.exe|\.7z|\.zip|\battachments\b|\bupimg\b|uploadfiles|templets|template|data\b|forumdata|includes|cache|jmxinvokerservlet|vhost|bbs|host|wwwroot|\bsite\b|root|hytop|flashfxp|bak|old|mdb|sql|backup|^java$|class|\.zip|\.rar|\.mdb|\.inc|\.sql|\.config|\.bak|/login.inc.php|/.svn/|/mysql/|config.inc.php|\.bak|wwwroot|网站备份|/gf_admin/|/DataBackup/|/Web.config|/web.config|/1.txt|/test.txt'

    iplist,timelist,urllist,statelist,sqllist, xsslist,senlist,otherurl,xssip,sqlip,senip,feifa = [],[],[],[],[],[],[],[],[],[],[],[]

    if not (os.path.exists('result')):
        os.mkdir(r'result')
    result = open('result/result.txt','a')
    sql_result = open('result/sql_result.txt','a')
    xss_result = open('result/xss_result.txt','a')
    sen_resule = open('result/sen_result.txt','a')

    with open(log,'r') as f:
        for i in f:
            iplist.append(i.split(' ')[0])
            ip = i.split(' ')[0]
            timelist.append(i.split(" ")[3])
            urllist.append(i.split(" ")[6])
            url = i.split(" ")[6]
            try:
                i.split(" ")[8]
            except:
                statelist.append('-')
            else:
                statelist.append(i.split(" ")[8])
            method=i.split(' ')[5][1:]
            if method == 'GET' or method == 'POST' or method =='HEAD':
                responsesql = re.findall(sql, url, re.I)

                if responsesql == []:

                    responsexss = re.findall(xss, url, re.I)

                    if responsexss == []:

                        responsesen = re.findall(sen, url, re.I)

                        if responsesen == []:

                            otherurl.append(url)

                        else:

                            senlist.append(url)

                            senip.append(ip)

                            #sen_resule.write('检测出敏感目录扫描')

                            sen_resule.write(str(i)+str(responsesen)+'\n')




                    else:

                        xsslist.append(url)

                        xssip.append(ip)

                        #xss_result.write('检测出xss攻击')

                        xss_result.write(str(i)+str(responsexss)+'\n')




                else:

                    sqllist.append(url)

                    sqlip.append(ip)

                    #sql_result.write('检测出sql攻击')

                    sql_result.write(str(i)+str(responsesql)+'\n')



            else:

                feifa.append(ip)

            result.write('非法请求:' + str(len(feifa)) + '次' + str(len(list(set(feifa)))) + '个ip\n')
            for i in list(set(feifa)):
                result.write(str(i)+'\n')
            result.write('sql注入攻击共有'+ str(len(sqllist)) + '次' + str(len(list(set(sqlip)))) + '个ip\n')
            for i in list(set(sqlip)):
                result.write(str(i)+'\n')
            result.write('XSS攻击共有'+ str(len(xsslist)) + '次' + str(len(list(set(xssip)))) + '个ip\n')
            for i in list(set(xssip)):
                result.write(str(i)+'\n')
            result.write('目录扫描攻击共有'+ str(len(senlist)) + '次' + str(len(list(set(senip)))) + '个ip\n')
            for i in list(set(senip)):
                result.write(str(i)+'\n')

    return 1


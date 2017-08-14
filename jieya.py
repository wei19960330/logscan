#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : whisper
# @Site    : https://github.com/wei19960330

import os
import sys
import subprocess

rardir = r'E:\7-Zip'



def dirhandle(str1):
    s = str1.rfind('\\')
    return str1[:s+1]

def eXtract(zip_dir):


    str2 = rardir+r'\7z x '+zip_dir+' -y -o"'+dirhandle(zip_dir)+'"'

    r1 = subprocess.call(str2,shell=True)

    return 1


if __name__ == '__main__':
    eXtract(r'D:\BaiduNetdiskDownload\test\log.rar')
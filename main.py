#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : whisper
# @Site    : https://github.com/wei19960330
# @File    : main.py

import sys
import re
import jieya






if __name__ == '__main__':
    str1='F:\web安全\日志分析\log.tar.gz'
    s = str1.rfind('\\')
    print str1[:str1.rfind('\\')+1]
#!/usr/bin/env python
# coding=utf8 
from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
import re
import json
import time
import random
import hashlib
import collections
import sys
from urllib import unquote

class Setting():
    # Choose function
    change_parameters_function = False
    change_headers_function = False
    change_cookies_function = False

    # Choose argument
    change_parameterNameSet = {}
    change_headerNameSet = {}
    change_cookieNameSet = {}


class Changer():
    def md5(self, mes):
        md5_str = hashlib.md5()   
        md5_str.update(mes)   
        return md5_str.hexdigest()

    def sha1(self, mes):
        sha1_str = hashlib.sha1()
        sha1_str.update(mes)
        return sha1_str.hexdigest()

    def sha256(self, mes):
        sha256_str = hashlib.sha256()
        sha256_str.update(mes)
        return sha256_str.hexdigest()

    # 程序会遍历change_parameterNameSet中的参数,进行一个个修改
    # 'string' parameterName 是要被修改的参数
    # {dict} parameters包含所有参数和数值
    # {dict} headers包含所有的头部
    # {dict} cookiesDict包含所有的cookie
    # 'string' method是方法
    # 'string' url 是链接
    def modify_parameters(self, parameterName, parameters, headers, cookiesDict, method, url):
        value = ' '
        if parameterName == '':
            do_something()
        elif parameterName == ' ':  
            do_something2() 
        return value

    def modify_headers(self, headerName, parameters, headers, cookiesDict, method, url):
        value = ' '
        if headerName == '':
            do_something()
        elif headerName == ' ':  
            do_something2() 
        return value


    def modify_cookies(self, cookieName, parameters, headers, cookiesDict, method, url):
        value = ' '
        if cookieName == '':
            do_something()
        elif cookieName == ' ':
            do_something2()
        return value





# ---------------------------------------------------------------------------------------------------------------------------- #

# Class BurpExtender (Required) contaning all functions used to interact with Burp Suite API
class BurpExtender(IBurpExtender, IHttpListener):

    def __init__(self):
        self.change_parameters_function = Setting.change_parameters_function
        self.change_headers_function = Setting.change_headers_function
        self.change_cookies_function = Setting.change_cookies_function

        # Choose argument
        self.change_parameterNameSet = Setting.change_parameterNameSet
        self.change_headerNameSet = Setting.change_headerNameSet
        self.change_cookieNameSet = Setting.change_cookieNameSet

    # define registerExtenderCallbacks: From IBurpExtender Interface 
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object (Burp Extensibility Feature)
        self._callbacks = callbacks
        # obtain an extension helpers object (Burp Extensibility Feature)
        # http://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html
        self._helpers = callbacks.getHelpers()
        # set our extension name that will display in Extender Tab
        self._callbacks.setExtensionName("Tophant_Sign")
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

    # print the process info to UI
    def log(self, parameters_values, headersDict, cookiesDict, method, url):
        mes =''' 
|- Get data: 
|      method: %s,
|      parameters: %s,
|      headers: %s,
|      cookie: %s,
|      url: %s ''' % (
    method, list(parameters_values.keys()), list(headersDict.keys()), list(cookiesDict.keys()), url)
        print(mes)
  
    # define processHttpMessage: From IHttpListener Interface 
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        # if tool is Repeater(64)/Intruder(32)
        if toolFlag not in {64,32}: 
            return None

        # determine if it's a request or a response:
        if messageIsRequest: 
            # Get the IExtensionHelpers
            IExHelper = self._helpers

            # Get the byte[] Request
            request_byte = messageInfo.getRequest()

            # Get An IRequestInfo
            request_info = IExHelper.analyzeRequest(messageInfo)

            # Get the body part(A str)
            bodybytes = request_byte[request_info.getBodyOffset():]
            body = IExHelper.bytesToString(bodybytes)

            # Get all parameters(A dict)
            IParameter = request_info.getParameters()
            parameters_info = {p.getName():p.getType() for p in IParameter if p.getTpye() in {0,1}}
            parameters_values = {p.getName():unquote(p.getValue()) for p in IParameter if p.getTpye() in {0,1}}

            # Get the header part(A list and A dict)
            # Example : 
            '''
            [u'POST /cms/rest.htm?sign=313D2D8CE96B84DF225EFA0E6677D1ED&loginToken=55a6d4fb975a9e4de1d4ccc0abdf56b1 HTTP/1.1'
            , u'Host: www.ddky.com:8050'
            , u'Content-Type: application/x-www-form-urlencoded'
            , u'Connection: close'
            , u'Accept: */*'
            , u'User-Agent: DingDangShopAppStore/4.16 CFNetwork/811.5.4 Darwin/16.6.0', u'Accept-Language: en-us', u'Accept-Encoding: gzip, deflate', u'Content-Length: 6609'
            ]
            '''
            headers = request_info.getHeaders()
            headersList = list(headers)
            headersDict = {}
            for item in headersList[1:]:
                pattern = re.search('(.+?):(.+)',item)
                headersDict[pattern.group(1).strip()] = pattern.group(2).strip()
            

            # Get the cookie(A dict)
            cookiesDict = {}
            try:
                cookies = headersDict['Cookie'].split(';')
            except KeyError,e:
                pass
            else:
                for cookie in cookies:
                    if cookie:
                        pattern = re.search('^(.+?)=(.*)', cookie)
                        cookiesDict[pattern.group(1).strip()] = pattern.group(2).strip()


            # Get Method(A string)
            method = request_info.getMethod()

            # Get URL
            url = unquote(str(request_info.getUrl()))

            # log
            if any([self.change_headers_function,self.change_parameters_function,self.change_cookies_function]):
                self.log(parameters_values, headersDict, cookiesDict, method, url)
                changer = Changer()

            # -- Headers --
            new_headers_list = headersList[:]
            if self.change_headers_function:
                new_headersDict = headersDict.copy()
                changer_f = changer.modify_headers

                if not self.change_headerNameSet:
                    print('[!] Error: No header name given. Skip')

                # Change headers
                for header in self.change_headerNameSet:
                    headerName = header
                    headerValue = str(changer_f(headerName, parameters_values, headersDict, cookiesDict, method, url))
                    # Change the value
                    if headerName in new_headersDict:
                        new_headersDict[headerName] = headerValue
                        # log
                        print('|- %s --> %s'%(headerName, headerValue))
                    else:
                        print('[!] Error: Header %s does not exist.Skip'%headerName)
                    
                # Build A new header
                modified_headers = [u'%s:%s'%(str(header), new_headersDict[header]) for header in new_headersDict]
                new_headers_list = [headersList[0]] + modified_headers

                # List<string> headers, bytes body
                messageInfo.setRequest(IExHelper.buildHttpMessage(new_headers_list, bodybytes))
                if self.change_parameters_function == True:
                    request_byte = IExHelper.buildHttpMessage(new_headers_list, bodybytes)
            
            # -- Cookies --
            if self.change_cookies_function:
                new_cookiesDict = cookiesDict.copy()
                changer_f = changer.modify_cookies

                if not self.change_cookieNameSet:
                    print('[!] Error: No cookie name given. Skip')
                    
                # Change Cookies
                for cookie in self.change_cookieNameSet:
                    cookieName = cookie
                    cookieValue = str(changer_f(cookieName, parameters_values, headersDict, cookiesDict, method, url))
                    # Change the value
                    if cookieName in new_cookiesDict:
                        new_cookiesDict[cookieName] = cookieValue
                        # log
                        print('|- %s --> %s'%(cookieName, cookieValue))
                    else:
                        print('[!] Error: Cookie %s does not exist. Skip'%cookieName)

                # Build A new cookie and header
                modified_cookies = ';'.join([u'%s:%s'%(str(cookie), new_cookiesDict[cookie]) for cookie in new_cookiesDict])
                new_headersDict['Cookie'] = modified_cookies
                modified_headers = [u'%s:%s'%(header, new_headersDict[header]) for header in new_headersDict]
                new_headers_list= [headersList[0]] + modified_headers
                # List<string> headers, bytes body
                messageInfo.setRequest(IExHelper.buildHttpMessage(new_headers_list, bodybytes))
                if self.change_parameters_function == True:
                    request_byte = IExHelper.buildHttpMessage(new_headers_list, bodybytes)

            # -- Parameters --
            if self.change_parameters_function:
                new_body_string = body[:]

                # Change parameters
                changer_f = changer.modify_parameters

                if not self.change_parameterNameSet:
                    print('[!] Error: No parameter name given. Skip')

                for parameter in self.change_parameterNameSet:

                    if parameter not in parameters_info:
                        print('[!] Error: Parameter %s does not exist.Skip'%parameter)
                        continue
                    parameterName = parameter   
                    parameterValue = str(changer_f(parameterName, parameters_values, headersDict, cookiesDict, method, url))
                    parameterType = parameters_info[parameterName]
                    # log
                    print('|- %s --> %s'%(parameterName, parameterValue))
                    if parameterType in {0,1}:
                        # Build a parameter Object and substitute the original one with it.
                        modified_para = IExHelper.buildParameter(parameterName, parameterValue, parameterType)
                        new_request_byte = IExHelper.updateParameter(request_byte, modified_para)
                        # Modify the request
                        messageInfo.setRequest(new_request_byte)
                    # if it's json type
                    elif parameterType == 6:
                        pattern = '"%s":".*?"'%parameterName
                        # Only change one parameter if several ones are matched (several parameters of the same names)
                        new_body_string = re.sub(pattern, '"%s":"%s"'%(parameterName,parameterValue), new_body_string, 1)
                        new_body_bytes = IExHelper.stringToBytes(new_body_string)
                        # Modify the request
                        messageInfo.setRequest(IExHelper.buildHttpMessage(new_headers_list, new_body_bytes))
                    else:
                        print(parameterType)
                        print('[!] Error: Action not supported for this parameter types.')
            return None              
    

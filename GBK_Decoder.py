# -*- coding:utf-8 -*-
# Burp Extension - URL decoder
# Copyright : Wesley Tan


from urllib import unquote, quote
import re

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from struct import pack
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName('GBK2310 Decoder')
        callbacks.registerMessageEditorTabFactory(self)
        
    # Called by MessageEditorTabFactory to build a IMessageEditorTab
    def createNewInstance(self, controller, editable): 
        return GBKDecoderTab(self, controller, editable)
        
class GBKDecoderTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable
        
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        return
        
    def getTabCaption(self):
        return "GBK2310 Decoder"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):    
        return True
    
    def setMessage(self, content, isRequest):
        if content is None:
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        else:
            if isRequest:
                r = self._helpers.analyzeRequest(content)
            else:
                r = self._helpers.analyzeResponse(content)

            # get the body
            msg = content[r.getBodyOffset():]
            header = content[0:r.getBodyOffset()]

            # msg is formed as an array，like array('b', [60, 33, 68]). Each character in the html is displayed in the decimal form.
            # GBK allowes each chinese word to be stored with two bytes, like \xcb\xb5, while these two bytes are shown as -53,-75 in the msg array
            # According to the GBK encoding principle, we can assume that all negative numbers in the msg array are a part of the gbk.
            # So what we do, is to retrieve all the negative numbers in the msg array, and then zip them by two numbers
            # like get （-53,-75), and transformed to ('\xcb\xb5') 
            message = ""
            header = ''.join([chr(i) for i in header])

            try:
                length = len(msg)
                index = 0
                while index < length:
                    if msg[index] > 0 :
                        tmp = chr(msg[index])
                        message += tmp
                    else:
                        tmp1 = pack('i', msg[index]).replace('\xff','')            
                        index += 1
                        tmp2 = pack('i', msg[index]).replace('\xff','')            
                        tmp = tmp1 + tmp2                                         
                        tmp = tmp.decode('gbk').encode('utf-8')
                        message += tmp
                    index += 1
            except Exception as e:
                message = msg
            
            self._txtInput.setText(header+message)
            self._txtInput.setEditable(self._editable)
        
        # save the original message to a variable
        self._prettymsg = msg
        self._currentMessage = content
        return None
        
    # This method returns the currently displayed message.
    #
    # @return The currently displayed message.
    # The hosting editor will call this method to retrieve the edited message from the messageTab
    # when isModified() returns true.
    def getMessage(self):    
        # if the message in the created MessageEditorTab has beed modified by the user,
        if self._txtInput.isTextModified():
            data = self._helpers.urlEncode(self._txtInput.getText())
            print 'data%s'%data
            # Reconstruct request/response
            r = self._helpers.analyzeRequest(self._currentMessage)
            return self._helpers.buildHttpMessage(r.getHeaders(), data)
        # else, just return 
        else:
            return self._currentMessage
        
    def isModified(self):
        return self._txtInput.isTextModified()
        
    def getSelectedData(self):
        return self._txtInput.getSelectedText()


    # When a request is made or a response is received, a messageTab is created. At this messageTab, setMessage
    # is called by the MessageTab to set the displayed message. If the user modify the message in the messageTab, 
    # isModified is called and return true, which make getMessage called by the hosting tab to get the modified 
    # message back to the hosting tab.
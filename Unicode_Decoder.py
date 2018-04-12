# Burp Extension - Unicode decoder
# Copyright : Wesley Tan
# 
# Burp can resolve utf-8 encoding
# but sometimes it can't, because the web server returns the unicode ,not in the utf-8 format.
# For example:
#
# Chinese characters: Nei   -- utf-8 : \xe5\x86\x85
# If the web server responds with 'e58585', burp can resolve it to 'Nei'
# But sometimes, web server replies it as unicode, not utf-8
# like \u624b\u673a..


from urllib import unquote, quote
import re

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName('Unicode Decoder')
        callbacks.registerMessageEditorTabFactory(self)
        
    # Called by MessageEditorTabFactory to build a IMessageEditorTab
    def createNewInstance(self, controller, editable): 
        return UnicodeDecoderTab(self, controller, editable)
        
class UnicodeDecoderTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable
        
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        return
        
    def getTabCaption(self):
        return "Unicode Decoder"
        
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
            header = content[0:r.getBodyOffset()]
            msg = content[r.getBodyOffset():]

            try:
                message = ''.join([chr(i) for i in msg])
                header = ''.join([chr(i) for i in header])
                pretty_msg = message.decode('unicode_escape').encode('utf-8') 
                self._txtInput.setText(header + pretty_msg)
                self._txtInput.setEditable(self._editable)    
            except Exception as e:
                print(str(e))
                self._txtInput.setText(content)
                self._txtInput.setEditable(self._editable)        
        
        # save the original message to a variable
        self._prettymsg = pretty_msg
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
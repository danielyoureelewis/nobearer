from burp import IBurpExtender, IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Remove Auth Header")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, requestResponse):
        if messageIsRequest:
            request = self._helpers.analyzeRequest(requestResponse)
            headers = request.getHeaders()
            new_headers = [h for h in headers if not h.lower().startswith("authorization")]

            body = requestResponse.getRequest()[request.getBodyOffset():]
            modified_request = self._helpers.buildHttpMessage(new_headers, body)
            requestResponse.setRequest(modified_request)

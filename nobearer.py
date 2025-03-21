from burp import IBurpExtender, IHttpListener, IScannerInsertionPointProvider, IScannerIssue
from java.net import URL
from java.util import ArrayList

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Auth Bypass Detector")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, requestResponse):
        if not messageIsRequest:  # Only process responses
            return
        
        request = self._helpers.analyzeRequest(requestResponse)
        headers = request.getHeaders()

        # Remove Authorization header
        new_headers = [h for h in headers if not h.lower().startswith("authorization")]
        body = requestResponse.getRequest()[request.getBodyOffset():]
        modified_request = self._helpers.buildHttpMessage(new_headers, body)

        # Send the modified request
        httpService = requestResponse.getHttpService()
        modified_response = self._callbacks.makeHttpRequest(httpService, modified_request)

        # Analyze the response
        response_info = self._helpers.analyzeResponse(modified_response.getResponse())
        status_code = response_info.getStatusCode()

        # If unauthorized request succeeds, create an issue
        if status_code == 200:
            self._callbacks.addScanIssue(CustomScanIssue(
                httpService,
                self._helpers.analyzeRequest(modified_response).getUrl(),
                [modified_response],  # Highlight request/response
                "Authentication Bypass",
                "Removing the Authorization header still returned 200 OK. This could indicate a potential authentication bypass vulnerability.",
                "High"
            ))

class CustomScanIssue(IScannerIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Firm"

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Ensure that authentication is strictly enforced on protected resources."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

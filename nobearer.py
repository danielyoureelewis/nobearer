from burp import IBurpExtender, IHttpListener, IScanIssue
from java.net import URL
from java.util import ArrayList

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Auth Bypass Detector")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, requestResponse):
        if not messageIsRequest:  # Ignore responses
            return
        
        request = self._helpers.analyzeRequest(requestResponse)
        headers = request.getHeaders()

        # Remove Authorization header
        new_headers = [h for h in headers if not h.lower().startswith("authorization")]
        body = requestResponse.getRequest()[request.getBodyOffset():]
        modified_request = self._helpers.buildHttpMessage(new_headers, body)

        # Send modified request
        httpService = requestResponse.getHttpService()
        modified_response = self._callbacks.makeHttpRequest(httpService, modified_request)

        # Check response status
        response_info = self._helpers.analyzeResponse(modified_response.getResponse())
        status_code = response_info.getStatusCode()

        if status_code == 200:
            issue = CustomScanIssue(
                httpService,
                self._helpers.analyzeRequest(modified_response).getUrl(),
                [modified_response],  # Include request/response
                "Authentication Bypass",
                "Removing the Authorization header still returned 200 OK. This could indicate a potential authentication bypass vulnerability.",
                "High"
            )
            self._callbacks.addScanIssue(issue)  # Corrected: Issue now implements IScanIssue fully

# Implement IScanIssue properly
class CustomScanIssue(IScanIssue):
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
        return 0  # Generic issue type

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"

    def getIssueDetail(self):
        return self._detail

    def getIssueBackground(self):
        return "Authentication bypass occurs when a protected resource is accessible without proper credentials. This may allow unauthorized users to access restricted data or functionality."

    def getRemediationDetail(self):
        return "Ensure that all protected resources enforce authentication and authorization properly."

    def getRemediationBackground(self):
        return "To mitigate this issue, implement strict authentication checks at both the client and server levels. Consider using session tokens, OAuth, or API key verification."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

from burp.api.montoya import BurpExtender as MontoyaExtender
from burp.api.montoya.http.handler import HttpHandler
from burp.api.montoya.http.message.requests import HttpRequest
from burp.api.montoya.http.message.responses import HttpResponse
from burp.api.montoya.core import Registration
from burp.api.montoya.scanner import AuditIssue, AuditIssueSeverity, AuditIssueConfidence

class BurpExtender(MontoyaExtender, HttpHandler):
    def initialize(self, callbacks):
        self.callbacks = callbacks
        self.api = callbacks.api()
        self.api.extension().set_name("Auth Bypass Detector")
        self.api.http().registerHttpHandler(self)

    def handleHttpRequest(self, request: HttpRequest, registration: Registration):
        # Remove Authorization header
        headers = request.headers()
        new_headers = [h for h in headers if not h.lower().startswith("authorization")]
        modified_request = request.with_headers(new_headers)

        # Send modified request
        httpService = request.http_service()
        modified_response = self.api.http().send_request(modified_request)

        # Check response status
        if modified_response.status_code() == 200:
            issue = AuditIssue(
                httpService,
                request.url(),
                [modified_request, modified_response],
                "Authentication Bypass",
                "Removing the Authorization header still returned 200 OK, indicating a possible authentication bypass vulnerability.",
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM
            )
            self.api.scanner().report_issue(issue)

        return request  # Forward original request

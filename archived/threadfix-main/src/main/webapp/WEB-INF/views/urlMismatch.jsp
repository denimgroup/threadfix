<%@ include file="/common/taglibs.jsp"%>

<html>
    <head>
        <title>Base URL mismatch</title>
    </head>
    <body>
        <h2>Base URL Mismatch</h2>
        <div>
            <p>
                The saved base URL is not the same as the one you use to connect to ThreadFix:
                <table>
                    <tr><td style="padding-right:20px; font-weight: bold;">Saved</td><td ng-non-bindable><c:out value="${savedBaseUrl}"/></td></tr>
                    <tr><td style="padding-right:20px; font-weight: bold;">Currently using</td><td ng-non-bindable><c:out value="${currentBaseUrl}"/></td></tr>
                </table>
            </p>
            <p>
                This can be due to the use of an alias, a change of protocol (like https),
                or some change in the server. The saved URL is used to send the vulnerabilities
                links by email or to defect trackers, so you may need to update it for proper behavior.
            </p>
            <c:if test="${empty redirectUrl}">
                <a class="btn" href="<spring:url value="/dashboard" htmlEscape="true"/>">Ignore and continue</a>
            </c:if>
            <c:if test="${not empty redirectUrl}">
                <a class="btn" href="${redirectUrl}">Ignore and continue</a>
            </c:if>
            <a class="btn" href="<spring:url value="/configuration/settings" htmlEscape="true"/>">Go to configuration page</a>
        </div>
    </body>
</html>

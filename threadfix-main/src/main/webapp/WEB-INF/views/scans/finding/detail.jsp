<h2>Finding Details</h2>

<div style="padding-bottom:10px">
    <c:if test="${ not empty finding.vulnerability }">
        <spring:url value="../../../vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">
            <spring:param name="vulnerabilityId" value="${ finding.vulnerability.id }" />
        </spring:url>
        <a class="btn" href="${ fn:escapeXml(vulnerabilityUrl) }">
            <c:out value="View Vulnerability"/>
        </a>
        <c:if test="${ canModifyVulnerabilities }">
            <spring:url value="{findingId}/merge" var="mergeUrl">
                <spring:param name="findingId" value="${ finding.id }"/>
            </spring:url>
            <a class="btn" href="${ fn:escapeXml(mergeUrl) }">Merge with Other Findings</a>
        </c:if>
    </c:if>
</div>

<br/>
<%@ include file="/WEB-INF/views/applications/sharedComponentTable.jsp" %>
<br/>
<table class="dataTable">
    <tbody>
    <c:if test="${ not empty finding.urlReference }">
        <tr>
            <td class="bold">Link</td>
            <td class="inputValue"><a ng-non-bindable id="sourceUrl" href="<c:out value="${ finding.urlReference }"/>" target="_blank"><c:out value="${ finding.urlReference }"/></a></td>
        </tr>
    </c:if>
    <tr>
        <td class="bold">Scanner Vulnerability</td>
        <td class="inputValue" id="scannerVulnerabilityType" ng-non-bindable><c:out value="${ finding.channelVulnerability.name }"/></td>
    </tr>
    <tr>
        <td class="bold">Scanner Severity</td>
        <td class="inputValue" id="scannerSeverity" ng-non-bindable><c:out value="${ finding.channelSeverity.name }"/></td>
    </tr>
    <tr>
        <td class="bold">Scanner Confidence Rating</td>
        <td class="inputValue" id=scannerConfidencRating" ng-non-bindable><c:out value="${ finding.confidenceRating }"/></td>
    </tr>
    <tr>
        <td class="bold">CWE Vulnerability</td>
        <td class="inputValue" id="genericVulnerabilityName">
                    <span ng-non-bindable tooltip="CWE-${ finding.channelVulnerability.genericVulnerability.displayId }">
                    <c:out value="${ finding.channelVulnerability.genericVulnerability.name }"/></span></td>
    </tr>
    <tr>
        <td class="bold">Severity</td>
        <td class="inputValue" id="genericSeverityName" ng-non-bindable><c:out value="${ finding.channelSeverity.severityMap.genericSeverity.displayName }"/></td>
    </tr>
    <c:if test="${ empty finding.dependency }">
        <tr>
            <td class="bold">Description</td>
            <td class="inputValue" id="longDescription" style="max-width:500px;word-wrap: break-word;" ng-non-bindable><c:out value="${ finding.longDescription }"/></td>
        </tr>
        <tr>
            <td class="bold">Path</td>
            <td class="inputValue" id="path" ng-non-bindable><c:out value="${ finding.surfaceLocation.path }"/></td>
        </tr>
        <tr>
            <td class="bold">Parameter</td>
            <td class="inputValue" id="parameter" ng-non-bindable><c:out value="${ finding.surfaceLocation.parameter }"/></td>
        </tr>
        <tr>
            <td class="bold">Native ID</td>
            <td class="inputValue" id="nativeId" ng-non-bindable>
                <c:if test="${ not empty finding.displayId }"><c:out value="${ finding.displayId }" /></c:if>
                <c:if test="${ empty finding.displayId }"><c:out value="${ finding.nativeId }" /></c:if>
            </td>
        </tr>
        <tr>
            <td class="bold" >Attack String</td>
            <td class="inputValue"><PRE id="attackString" ng-non-bindable><c:out value="${ finding.attackString }"/></PRE></td>
        </tr>
        <tr class="odd">
            <td class="bold" valign=top>Scanner Detail</td>
            <td class="inputValue" style="word-wrap: break-word;list-style: square"><PRE id="scannerDetail" ng-non-bindable><c:out value="${ finding.scannerDetail }"/></PRE></td>
        </tr>
        <tr>
            <td class="bold" valign=top>Scanner Recommendation</td>
            <td class="inputValue" style="word-wrap: break-word;list-style: square"><PRE id="scannerRecommendation" ng-non-bindable><c:out value="${ finding.scannerRecommendation }"/></PRE></td>
        </tr>
        <tr>
            <td class="bold" valign=top>Attack Request</td>
            <td class="inputValue" style="word-wrap: break-word;"><PRE id="attackRequest" ng-non-bindable><c:out value="${ finding.attackRequest }"/></PRE></td>
        </tr>
        <tr>
            <td class="bold" valign=top>Attack Response</td>
            <td class="inputValue" style="word-wrap: break-word;"><PRE id="attackResponse" ng-non-bindable><c:out value="${ finding.attackResponse }"/></PRE></td>
        </tr>
    </c:if>
    <c:if test="${ not empty finding.dependency }">
        <tr>
            <td class="bold">Reference</td>
            <td class="inputValue" id="dependency" ng-non-bindable>
                <c:out value="${ finding.dependency.refId } "/>
                (<a target="_blank" href="<c:out value="${ finding.dependency.refLink }"/>">View</a>)
            </td>
        </tr>
        <tr>
            <td class="bold" valign=top>File Name</td>
            <td class="inputValue" style="word-wrap: break-word;"><PRE id="dependencyFileName" ng-non-bindable><c:out value="${ finding.dependency.componentName }"/></PRE></td>
        </tr>
        <tr>
            <td class="bold" valign=top>File Path</td>
            <td class="inputValue" style="word-wrap: break-word;"><PRE id="dependencyFilePath" ng-non-bindable><c:out value="${ finding.dependency.componentFilePath }"/></PRE></td>
        </tr>
        <tr>
            <td class="bold" valign=top>Description</td>
            <td class="inputValue" style="word-wrap: break-word;"><PRE id="dependencyDesc" ng-non-bindable><c:out value="${ finding.dependency.description }"/></PRE></td>
        </tr>
        <c:if test="${ not empty finding.scannerRecommendation }">
            <tr>
                <td class="bold" valign=top>Scanner Recommendation</td>
                <td class="inputValue" style="word-wrap: break-word;list-style: square"><PRE id="scannerRecommendationInDependency" ng-non-bindable><c:out value="${ finding.scannerRecommendation }"/></PRE></td>
            </tr>
        </c:if>
    </c:if>
    <tr>
        <td class="bold" valign=top>Raw Finding</td>
        <td class="inputValue" style="word-wrap: break-word;"><PRE id="rawFinding" ng-non-bindable><c:out value="${ finding.rawFinding }"/></PRE></td>
    </tr>
    </tbody>
</table>

<c:if test="${ not empty finding.dataFlowElements }">
    <h3>Data Flow</h3>
    <table class="dataTable">
        <tbody>
        <c:forEach var="flowElement" items="${ finding.dataFlowElements }">
            <tr>
                <td class="bold">File Name</td>
                <td class="inputValue" ng-non-bindable><c:out value="${ flowElement.sourceFileName }"/></td>
            </tr>
            <tr>
                <td class="bold">Line Number</td>
                <td class="inputValue" ng-non-bindable><c:out value="${ flowElement.lineNumber }"/></td>
            </tr>
            <tr>
                <td class="bold">Line Text</td>
                <td class="inputValue"><code ng-non-bindable><c:out value="${ flowElement.lineText }"/></code></td>
            </tr>
            <tr>
                <td class="bold">Column Number</td>
                <td class="inputValue" ng-non-bindable><c:out value="${ flowElement.columnNumber }"/></td>
            </tr>
            <tr>
                <td class="bold">Sequence</td>
                <td class="inputValue" ng-non-bindable><c:out value="${ flowElement.sequence }"/></td>
            </tr>
            <tr>
                <td colspan="2">============================================================</td>
            </tr>
        </c:forEach>
        </tbody>
    </table>
</c:if>

<h2>Vulnerability Details
	<span style="font-size:10pt;">
		<div class="btn-group" ng-controller="VulnOperationsController">
            <button id="actionItems" ng-show="showActionButton" class="btn dropdown-toggle" data-toggle="dropdown" type="button">
                Action <span class="caret"></span>
            </button>
            <ul class="dropdown-menu">
                <c:if test="${ canModifyVulnerabilities }">
                    <li ng-show="vulnerability.active && !vulnerability.hidden"><a id="closeVulnerabilityLink" class="pointer" ng-click="closeVuln()">Close Vulnerability</a></li>
                    <li ng-show="!vulnerability.active && !vulnerability.hidden"><a id="openVulnerabilityLink" class="pointer" ng-click="openVuln()">Open Vulnerability</a></li>
                    <li ng-show="!vulnerability.isFalsePositive"><a id="markFalsePositiveLink" class="pointer" ng-click="markFalsePositive()">Mark as False Positive</a></li>
                    <li ng-show="vulnerability.isFalsePositive"><a id="unmarkFalsePositiveLink" class="pointer" ng-click="unmarkFalsePositive()">Unmark False Positive</a></li>
                </c:if>
                <li ng-show="vulnerability.defect"><a id="viewDefectLink" class="pointer" ng-click="viewDefect()">View Defect</a></li>
                <c:if test="${ canSubmitDefects}">
                    <li ng-show="vulnerability.app.defectTracker && !vulnerability.defect"><a class="pointer" ng-click="showSubmitDefectModal()">Create Defect</a></li>
                    <li ng-show="vulnerability.app.defectTracker && !vulnerability.defect"><a class="pointer" ng-click="showMergeDefectModal()">Add to Existing Defect</a></li>
                </c:if>
                <c:if test="${ canModifyVulnerabilities }">
                    <li><a id="taggingLink" class="pointer" ng-click="tagVuln(vulnTags)">Add Tag</a></li>
                </c:if>
            </ul>
        </div>
    </span>
    <span id="tag{{ tag.name }}" ng-repeat="tag in vulnerability.tags" class="badge pointer" ng-class="{'badge-vulnerability-tag': true}" ng-click="goToTag(tag)">{{ tag.name }}</span>
    <span id="version{{ version.name}}" ng-repeat="version in vulnerability.versions" class="badge" ng-class="{'badge-vulnerability-version': true}">{{ version.name }}</span>
</h2>

<%@ include file="/WEB-INF/views/successMessage.jspf" %>
<%@ include file="/WEB-INF/views/errorMessage.jspf"%>
<%@ include file="/WEB-INF/views/scans/finding/editManualFindingForm.jsp" %>
<%@ include file="/WEB-INF/views/scans/finding/editDescriptionFindingForm.jsp" %>

<h3 style="padding-top:0;">
    <span class="label badge {{ badgeClassMap[vulnerability.genericSeverity.intValue] }}">
        {{ vulnerability.genericSeverity.displayName }}
    </span>
    <span tooltip="CWE-{{ vulnerability.genericVulnerability.displayId }}">{{ vulnerability.vulnerabilityName }}</span>
    -- <a id="cweLink" href="http://cwe.mitre.org/data/definitions/{{ vulnerability.genericVulnerability.displayId }}.html" target="_blank">CWE Entry</a>
</h3>

<c:set var="editVisible" value="false"/>

<c:forEach var="finding" items="${ vulnerability.findings }">
    <c:if test="${ finding.scan.applicationChannel.channelType.name == 'Manual'}">
        <c:set var="editVisible" value="true"/>
    </c:if>
</c:forEach>

<div ng-if="findings">
    <%@ include file="findingsTable.jsp" %>
</div>

<h4>Status</h4>
<div id="vulnHistory">
    <div class="grey-background">
        <table class="dataTable table">
            <thead>
                <tr>
                    <th colspan="3">
                        <span ng-if="vulnerability.active" class="badge">open</span>
                        <span ng-if="!vulnerability.active" class="badge badge-success">closed</span>
                        <span ng-if="vulnerability.isFalsePositive" class="badge badge-info">false positive</span>
                        <span ng-if="vulnerability.hidden" class="badge badge-inverse">hidden</span>
                    </th>
                </tr>
            </thead>
            <tbody>
                <tr ng-if="vulnerability.humanTimes.openTime">
                    <td class=bold>Open date<td>
                    <td>{{ vulnerability.humanTimes.openTime }}<td>
                </tr>
                <tr ng-if="vulnerability.humanTimes.wafRuleGeneratedTime">
                    <td class=bold>WAF rule generated<td>
                    <td>{{ vulnerability.humanTimes.wafRuleGeneratedTime }}<td>
                </tr>
                <tr ng-if="vulnerability.humanTimes.closeTime">
                    <td class=bold>Found closed by scanner<td>
                    <td>{{ vulnerability.humanTimes.closeTime }}<td>
                </tr>
             </tbody>
        </table>
    </div>
    <div ng-if="vulnerability.defect" style="margin-left:30px;" class="grey-background">
        <table class="dataTable table">
            <thead>
                <tr>
                    <th colspan="3">
                    <a ng-href="{{ vulnerability.defect.defectURL }}" target="_blank" class="badge">
                        Issue {{ vulnerability.defect.nativeId }} ({{ vulnerability.defect.status }})
                    </a>
                    - {{ vulnerability.app.defectTracker.name }}
                    </th>
                </tr>
            </thead>
            <tbody>
                <tr ng-if="vulnerability.humanTimes.defectSubmittedTime">
                    <td class=bold>Submitted date<td>
                    <td>{{ vulnerability.humanTimes.defectSubmittedTime }}<td>
                </tr>
                <tr ng-if="vulnerability.humanTimes.defectClosedTime">
                    <td class=bold>Marked as closed by tracker<td>
                    <td>{{ vulnerability.humanTimes.defectClosedTime }}<td>
                </tr>
             </tbody>
        </table>
    </div>
</div>

<div ng-show="links">
    <h4>External Links</h4>
    <span ng-repeat="link in links">
        {{ link.scannerName }}: <a href="{{ link.urlReference }}" target="_blank">{{ link.urlReference }}</a> <br/>
    </span>
</div>

<h4>Comments</h4>
<%@ include file="/WEB-INF/views/applications/vulnComments.jsp" %>
<c:if test="${ canSubmitComments }">
    <a id="addCommentButton" class="btn" ng-click="openCommentModal()">Add Comment</a>
</c:if>

<br/>

<div ng-controller="DocumentFormController">
    <h4>Files</h4>
    <%@ include file="/WEB-INF/views/applications/docsTable.jsp" %>
    <c:if test="${ canModifyVulnerabilities }">
        <a id="uploadDocVulnModalLink" class="btn" ng-click="showUploadForm()">Add File</a>
    </c:if>
</div>

<c:if test="${isEnterprise}">
    <jsp:include page="/app/organizations/${ vulnerability.application.organization.id }/applications/${ vulnerability.application.id }/vulnerabilities/${ vulnerability.id }/history"/>
</c:if>

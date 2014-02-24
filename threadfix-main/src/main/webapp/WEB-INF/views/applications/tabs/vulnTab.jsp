
<div ng-controller="VulnTableController">
    <div class="pagination">
        <pagination total-items="<c:out value="${numVulns}"/>" max-size="5" page="page"></pagination>
    </div>

    <div ng-hide="vulns" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <table ng-show="vulns" class="table sortable table-hover tf-colors" id="anyid">
        <thead>
            <tr>
                <th style="width:8px;"></th>
                <th class="pointer" style="min-width:70px">
                    Severity<span id="headerCaret2" class="caret-down"></span>
                </th>
                <th class="pointer">
                    Type<span id="headerCaret1" class="caret-down"></span>
                </th>
                <th class="pointer">
                    Path<span id="headerCaret3" class="caret-down"></span>
                </th>
                <th class="pointer" style="min-width:90px;">
                    Parameter<span id="headerCaret4" class="caret-down"></span>
                </th>
                <th style="width:25px;"></th>
                <th style="width:65px;"></th>
            </tr>
        </thead>
        <tbody>
            <tr ng-repeat="vuln in vulns" class="bodyRow pointer" ng-class="{
                    error: vuln.severityName === 'Critical',
                    warning: vuln.severityName === 'High',
                    success: vuln.severityName === 'Medium',
                    info: vuln.severityName === 'Info' || vuln.severityName === 'Low'
                    }">
                <td class="pointer">
                    <span id="caret{{ vuln.id }}" class="caret-right"></span>
                </td>
                <td class="pointer" id="severity{{ $index }}"> {{ vuln.severityName }} </td>
                <td class="pointer" id="type{{ $index }}">
                    {{ vuln.vulnerabilityName }}
                </td>

                <!-- TODO dependencies -->
                <td class="pointer" id="path{{ $index }}"> {{ vuln.path }} </td>
                <td class="pointer" id="parameter{{ $index }}"> {{ vuln.parameter }} </td>
                <%--<c:if test="${ not empty vulnerability.originalFinding.dependency }">--%>
                    <%--<td class="pointer" colspan="2">--%>
                        <%--<c:out value="${ vulnerability.originalFinding.dependency.cve } "/>--%>
                        <%--(<a target="_blank" id="cve{{ $index }}" href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=${ vulnerability.originalFinding.dependency.cve }">View</a>)--%>
                    <%--</td>--%>
                <%--</c:if>--%>

                <!-- TODO defects -->
                <%--<c:if test="${ not empty application.defectTracker }">--%>
                    <%--<td >--%>
                        <%--<c:if test="${ not empty vulnerability.defect }">--%>
                            <%--<div  class="tooltip-container" data-placement="left" title="<c:out value="${ vulnerability.defect.nativeId }"/> (<c:out value="${ vulnerability.defect.status }"/>)" style="width:100%;text-align:right;">--%>
                                <%--<a id="bugLink{{ $index }}"--%>
                                   <%--target="_blank"--%>
                                        <%--<c:if test="${ not empty vulnerability.defect.defectURL }"> href="<c:out value="${ vulnerability.defect.defectURL }"/>" </c:if> >--%>
                                    <%--<c:choose>--%>
                                        <%--<c:when test="${ openCodes.contains(vulnerability.defect.status) }">--%>
                                            <%--<img src="<%=request.getContextPath()%>/images/icn_bug_red_stroke.png" class="transparent_png" alt="Threadfix" />--%>
                                        <%--</c:when>--%>
                                        <%--<c:when test="${ closedCodes.contains(vulnerability.defect.status) }">--%>
                                            <%--<img src="<%=request.getContextPath()%>/images/icn_bug_grn_stroke.png" class="transparent_png" alt="Threadfix" />--%>
                                        <%--</c:when>--%>
                                        <%--<c:otherwise>--%>
                                            <%--<img src="<%=request.getContextPath()%>/images/icn_bug_yellow_stroke.png" class="transparent_png" alt="Threadfix" />--%>
                                        <%--</c:otherwise>--%>
                                    <%--</c:choose>--%>
                                <%--</a>--%>
                            <%--</div>--%>
                        <%--</c:if>--%>
                    <%--</td>--%>
                <%--</c:if>--%>
                <!-- TODO merged Findings -->
                <%--<td class="expandableTrigger">--%>
                    <%--<c:if test="${fn:length(vulnerability.findings) > 1 }">--%>
                        <%--<div id="findingIcon{{ $index }}"  class="tooltip-container" data-placement="left" title="<c:out value=""/> Findings" style="text-align:left;">--%>
                            <%--<img src="<%=request.getContextPath()%>/images/icn_fork_arrow25x25.png" class="transparent_png" alt="Threadfix" />--%>
                        <%--</div>--%>
                    <%--</c:if>--%>
                <%--</td>--%>
                <!-- TODO vuln link -->
                <%--<td>--%>
                    <%--<spring:url value="{appId}/vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">--%>
                        <%--<spring:param name="appId" value="${ application.id }" />--%>
                        <%--<spring:param name="vulnerabilityId" value="${ vulnerability.id }" />--%>
                    <%--</spring:url>--%>
                    <%--<a id="vulnName${index}" href="${ fn:escapeXml(vulnerabilityUrl) }">--%>
                        <%--View More--%>
                    <%--</a>--%>
                <%--</td>--%>
            </tr>

            <!-- TODO deal with expandables -->
            <%--<tr class="bodyRow <c:out value="${ color }"/> expandable ${ rowClass } ${ hideClass }">--%>
                <%--<c:set var="numColumns" value="8"/>--%>
                <%--<c:if test="${ not empty application.defectTracker }">--%>
                    <%--<c:set var="numColumns" value="9"/>--%>
                <%--</c:if>--%>
                <%--<td colspan="<c:out value="${ numColumns }"/>">--%>
                    <%--<div id="vulnInfoDiv${vulnerability.id}" class="collapse">--%>
                        <%--<div class="left-tile">--%>
                            <%--<c:if test="${not empty vulnerability.findings}">--%>
                                <%--<h4>Scan History</h4>--%>
                                <%--<div class="report-image" style="width:422px;margin-bottom:20px;background-color:#FFF;padding:0px;">--%>
                                    <%--<table class="table" style="margin-bottom:0px;">--%>
                                        <%--<thead class="table">--%>
                                        <%--<tr class="left-align">--%>
                                            <%--<th class="first">Channel</th>--%>
                                            <%--<th>Scan Date</th>--%>
                                            <%--<th class="last">User</th>--%>
                                        <%--</tr>--%>
                                        <%--</thead>--%>
                                        <%--<tbody>--%>
                                        <%--<c:forEach var="finding" items="${ vulnerability.findings }" varStatus="status">--%>
                                            <%--<tr class="left-align bodyRow">--%>
                                                <%--<td id="scan${ status.count }ChannelType"><c:out--%>
                                                        <%--value="${ finding.scan.applicationChannel.channelType.name }" /></td>--%>
                                                <%--<td id="scan${ status.count }ImportTime"><fmt:formatDate value="${ finding.scan.importTime.time }"--%>
                                                                                                         <%--type="both" dateStyle="short" timeStyle="medium" /></td>--%>
                                                <%--<td id="scan${ status.count }ChannelType${ status.count }"><c:if test="${ not empty finding.scan.user }">--%>
                                                    <%--<!-- Got info from scan, the normal case -->--%>
                                                    <%--<c:out value="${ finding.scan.user.name}" />--%>
                                                <%--</c:if> <c:if--%>
                                                        <%--test="${ empty finding.scan.user and not empty finding.user }">--%>
                                                    <%--<!-- Got info from finding, probably a manual scan -->--%>
                                                    <%--<c:out value="${ finding.user.name}" />--%>
                                                <%--</c:if> <c:if test="${ empty finding.scan.user and empty finding.user }">--%>
                                                    <%--No user found. Probably a remote scan.--%>
                                                <%--</c:if></td>--%>
                                            <%--</tr>--%>
                                        <%--</c:forEach>--%>
                                        <%--</tbody>--%>
                                    <%--</table>--%>
                                <%--</div>--%>
                            <%--</c:if>--%>
                        <%--</div>--%>

                        <%--<div class="right-tile">--%>
                            <%--<h4>Comments</h4>--%>
                            <%--<div class="report-image" id="commentDiv${ vulnerability.id }" style="width:450px;margin-bottom:10px;">--%>
                                <%--<%@ include file="/WEB-INF/views/applications/vulnComments.jsp" %>--%>
                            <%--</div>--%>
                            <%--<br>--%>
                            <%--<%@include file="/WEB-INF/views/applications/modals/vulnCommentModal.jsp"%>--%>
                        <%--</div>--%>
                    <%--</div>--%>
                <%--</td>--%>
            <%--</tr>--%>
        </tbody>
    </table>

    <%--<c:if test="${ not empty application.scans and numVulns > 0 }"> --%>

        <%--<spring:url value="{appId}/falsepositives/mark" var="markFPUrl">--%>
            <%--<spring:param name="appId" value="${ application.id }" />--%>
        <%--</spring:url>--%>
        <%--<form:form modelAttribute="falsePositiveModel" method="post" action="${ fn:escapeXml(markFPUrl) }">--%>
        <%----%>
        <%--<spring:url value="{appId}/table" var="tableUrl">--%>
            <%--<spring:param name="appId" value="${ application.id }"/>--%>
        <%--</spring:url>--%>
        <%----%>
        <%--<spring:url value="{appId}/table/close" var="closeUrl">--%>
            <%--<spring:param name="appId" value="${ application.id }"/>--%>
        <%--</spring:url>--%>
        <%----%>
        <%--<spring:url value="{appId}/falsePositives/mark" var="fpUrl">--%>
            <%--<spring:param name="appId" value="${ application.id }"/>--%>
        <%--</spring:url>--%>
        <%----%>
        <%--<c:if test="${ canModifyVulnerabilities || canSubmitDefects }">--%>
            <%--<div id="btnDiv1" class="btn-group">--%>
                <%--<button id="actionButton1" class="btn dropdown-toggle" data-toggle="dropdown" type="button">Action <span class="caret"></span></button>--%>
                <%--<ul class="dropdown-menu">--%>
                    <%--<li class="submitDefectActionLink"--%>
                        <%--<c:if test="${ empty application.defectTracker }">--%>
                            <%--style="display:none"--%>
                        <%--</c:if>--%>
                    <%-->--%>
                        <%--<a id="submitDefectButton" href="#submitDefectModal" data-toggle="modal" data-has-function="">--%>
                            <%--Submit Defect--%>
                        <%--</a>--%>
                    <%--</li>--%>
                    <%--<li class="missingDefectTrackerMessage" id = "missingDefectTrackerMessage"--%>
                        <%--<c:if test="${ not empty application.defectTracker }">--%>
                            <%--style="display:none"--%>
                        <%--</c:if>--%>
                        <%--<c:if test="${ empty application.defectTracker && !canManageApplications }">--%>
                            <%--data-has-no-manage-app-permisson="true"--%>
                        <%--</c:if>--%>
                    <%-->--%>
                        <%--<a class="missingDefectTrackerMessage" href="#">--%>
                            <%--Submit Defect--%>
                        <%--</a>--%>
                    <%--</li>--%>
                    <%----%>
                    <%--<li class="submitDefectActionLink"--%>
                        <%--<c:if test="${ empty application.defectTracker }">--%>
                            <%--style="display:none"--%>
                        <%--</c:if>--%>
                    <%-->--%>
                        <%--<a id="mergeDefectButton" href="#mergeDefectModal" data-toggle="modal" data-has-function="">--%>
                            <%--Merge Defect--%>
                        <%--</a>--%>
                    <%--</li>--%>
                    <%--<li class="missingDefectTrackerMessage"--%>
                        <%--<c:if test="${ not empty application.defectTracker }">--%>
                            <%--style="display:none"--%>
                        <%--</c:if>--%>
                        <%--<c:if test="${ empty application.defectTracker && !canManageApplications }">--%>
                            <%--data-has-no-manage-app-permisson="true"--%>
                        <%--</c:if>--%>
                    <%-->--%>
                        <%--<a class="missingDefectTrackerMessage" href="#" >--%>
                            <%--Merge Defect--%>
                        <%--</a>--%>
                    <%--</li>--%>
                                <%----%>
                    <%--<c:if test="${ canModifyVulnerabilities}"><li><a id="markClosedButton" onclick="javascript:submitVulnTableOperation('${ closeUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark Closed</a></li></c:if>--%>
                    <%--<c:if test="${ canModifyVulnerabilities}"><li><a id="markFalsePositiveButton" onclick="javascript:submitVulnTableOperation('${ fpUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark False Positive</a></li></c:if>--%>
                <%--</ul>--%>
            <%--</div>--%>
        <%--</c:if>--%>
        <%----%>
        <%--<span style="float:right">--%>
            <%--<a class="btn" id="expandAllVulns">Expand All</a>--%>
            <%--<a class="btn" id="collapseAllVulns">Collapse All</a>--%>
        <%--</span>--%>
        <%----%>
        <%--<%@ include file="/WEB-INF/views/applications/tabs/filter.jspf" %>--%>
        <%----%>
        <%--<%@ include file="/WEB-INF/views/applications/tabs/defaultTableDiv.jspf" %>--%>
        <%----%>
        <%--<c:if test="${ canModifyVulnerabilities || canSubmitDefects }">--%>
            <%--<div id="btnDiv2" class="btn-group">--%>
                <%--<button id="actionButton2" class="btn dropdown-toggle" data-toggle="dropdown" type="button">Action <span class="caret"></span></button>--%>
                <%--<ul class="dropdown-menu">--%>
                    <%--<li class="submitDefectActionLink"--%>
                        <%--<c:if test="${ empty application.defectTracker }">--%>
                            <%--style="display:none"--%>
                        <%--</c:if>--%>
                    <%-->--%>
                        <%--<a id="submitDefectButton" href="#submitDefectModal" data-toggle="modal" data-has-function="">--%>
                            <%--Submit Defect--%>
                        <%--</a>--%>
                    <%--</li>--%>
                    <%--<li class="missingDefectTrackerMessage"--%>
                        <%--<c:if test="${ not empty application.defectTracker }">--%>
                            <%--style="display:none"--%>
                        <%--</c:if>--%>
                        <%--<c:if test="${ empty application.defectTracker && !canManageApplications }">--%>
                            <%--data-has-no-manage-app-permisson="true"--%>
                        <%--</c:if>--%>
                    <%-->--%>
                        <%--<a class="missingDefectTrackerMessage" href="#" >--%>
                            <%--Submit Defect--%>
                        <%--</a>--%>
                    <%--</li>		--%>
        <%----%>
                    <%--<li class="submitDefectActionLink"--%>
                        <%--<c:if test="${ empty application.defectTracker }">--%>
                            <%--style="display:none"--%>
                        <%--</c:if>--%>
                    <%-->--%>
                        <%--<a id="mergeDefectButton" href="#mergeDefectModal" data-toggle="modal" data-has-function="">--%>
                            <%--Merge Defect--%>
                        <%--</a>--%>
                    <%--</li>--%>
                    <%--<li class="missingDefectTrackerMessage"--%>
                        <%--<c:if test="${ not empty application.defectTracker }">--%>
                            <%--style="display:none"--%>
                        <%--</c:if>--%>
                        <%--<c:if test="${ empty application.defectTracker && !canManageApplications }">--%>
                            <%--data-has-no-manage-app-permisson="true"--%>
                        <%--</c:if>--%>
                    <%-->--%>
                        <%--<a class="missingDefectTrackerMessage" href="#" >--%>
                            <%--Merge Defect--%>
                        <%--</a>--%>
                    <%--</li>--%>
        <%----%>
                    <%--<c:if test="${ canModifyVulnerabilities}"><li><a id="markClosedButton" onclick="javascript:submitVulnTableOperation('${ closeUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark Closed</a></li></c:if>--%>
                    <%--<c:if test="${ canModifyVulnerabilities}"><li><a id="markFalsePositiveButton" onclick="javascript:submitVulnTableOperation('${ fpUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark False Positive</a></li></c:if>--%>
                <%--</ul>--%>
            <%--</div>--%>
        <%--</c:if>--%>
        <%----%>
        <%--</form:form>--%>

    <%--</c:if>--%>

    <%--<c:if test="${ numVulns == 0 }">--%>
        <%--<c:set var="notCloseable" value="true"/>--%>
        <%--<c:set var="errorMessage" value="No active Vulnerabilities found."/>--%>
        <%--<%@ include file="/WEB-INF/views/errorMessage.jsp" %>--%>
    <%--</c:if>--%>
</div>
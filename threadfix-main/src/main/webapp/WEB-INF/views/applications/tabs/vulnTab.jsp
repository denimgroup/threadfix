
<tab ng-controller="VulnTableController"
     ng-init="numVulns = <c:out value="${numVulns}"/>"
     heading="{{ heading }}">

    <div ng-show="empty" class="empty-tab-drop-area">
        <div>Drop a scan here to upload.</div>
    </div>

    <!-- TODO add DRAG SCAN HERE area-->
    <div ng-hide="empty || vulns" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <div ng-show="vulns">
        <div class="pagination no-margin" ng-show="numVulns > 100" >
            <pagination class="no-margin" total-items="numVulns / 10" max-size="5" page="page"></pagination>

            <input  ng-enter="goToPage()" style="width:50px" type="number" ng-model="pageInput"/>
            <button class="btn" ng-click="goToPage()"> Go to Page </button>
            <span ng-show="loading" style="float:right" class="spinner dark"></span>
        </div>

        <table class="table sortable table-hover tf-colors" id="anyid">
            <thead>
                <tr>
                    <c:if test="${ (not hideCheckboxes) and (canModifyVulnerabilities || canSubmitDefects) }">
                        <th style="width:22px" class="first unsortable"><input type="checkbox" id="chkSelectAll" ng-click="checkAll"></th>
                    </c:if>
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
                <tr ng-click="expand(vuln)" ng-repeat-start="vuln in vulns" class="bodyRow pointer" ng-class="{
                        error: vuln.severityName === 'Critical',
                        warning: vuln.severityName === 'High',
                        success: vuln.severityName === 'Medium',
                        info: vuln.severityName === 'Info' || vuln.severityName === 'Low'
                        }">
                    <c:if test="${ (not hideCheckboxes) and (canModifyVulnerabilities || canSubmitDefects) }">
                        <td>
                            <input class="vulnIdCheckbox" id="vulnerabilityIds{{ index }}" type="checkbox" value="{{ vuln.id }}" name="vulnerabilityIds">
                            <input class="vulnIdCheckboxHidden" type="hidden" value="on" name="_vulnerabilityIds">
                        </td>
                    </c:if>
                    <td class="pointer">
                        <span ng-class="{ expanded: team.expanded }" id="caret{{ vuln.id }}" class="caret-right"></span>
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
                    <td class="expandableTrigger">
                        <div ng-show="vuln.findings.length > 1" id="findingIcon{{ $index }}" class="tooltip-container" data-placement="left" title="{{ vuln.findings.length }} Findings" style="text-align:left;">
                            <img src="<%=request.getContextPath()%>/images/icn_fork_arrow25x25.png" class="transparent_png" alt="Threadfix" />
                        </div>
                    </td>
                    <td>
                        <a id="vulnName${index}" ng-click="goTo(vuln)">
                            View More
                        </a>
                    </td>
                </tr>

                <tr ng-repeat-end ng-show="vuln.expanded" class="bodyRow expandable" ng-class="{
                        error: vuln.severityName === 'Critical',
                        warning: vuln.severityName === 'High',
                        success: vuln.severityName === 'Medium',
                        info: vuln.severityName === 'Info' || vuln.severityName === 'Low'
                        }">
                    <c:set var="numColumns" value="8"/>
                    <c:if test="${ not empty application.defectTracker }">
                        <c:set var="numColumns" value="9"/>
                    </c:if>
                    <td colspan="<c:out value="${ numColumns }"/>">
                        <div id="vulnInfoDiv">
                            <div class="left-tile">
                                <h4>Scan History</h4>
                                <div class="vuln-table-box" style="width:422px;margin-bottom:20px;background-color:#FFF;padding:0px;">
                                    <table class="table" style="margin-bottom:0px;">
                                        <thead class="table">
                                            <tr class="left-align">
                                                <th class="first">Channel</th>
                                                <th>Scan Date</th>
                                                <th class="last">User</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr ng-repeat="finding in vuln.findings" class="left-align bodyRow">
                                                <td id="scan{{ $index }}ChannelType"> {{ finding.scannerName }} </td>
                                                <td id="scan{{ $index }}ImportTime"> {{ finding.importTime }} </td>
                                                <td id="scan{{ $index }}ChannelType{{ $index }}">
                                                    <div ng-show="finding.scanOrManualUser"> {{ finding.scanOrManualUser.name }}</div>
                                                    <div ng-hide="finding.scanOrManualUser"> No user found. Probably a remote scan.</div>
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>

                            <div class="right-tile">
                                <h4>Comments</h4>
                                <div class="vuln-table-box" id="commentDiv${ vulnerability.id }" style="width:450px;margin-bottom:10px;">
                                    <%@ include file="/WEB-INF/views/applications/vulnComments.jsp" %>
                                </div>
                                <br>
                                <%@include file="/WEB-INF/views/applications/modals/vulnCommentModal.jsp"%>
                            </div>
                        </div>
                    </td>
                </tr>
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

</tab>
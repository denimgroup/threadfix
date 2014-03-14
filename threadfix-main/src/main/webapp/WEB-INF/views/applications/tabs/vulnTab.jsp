<tab ng-controller="VulnTableController"
     ng-init="numVulns = <c:out value="${numVulns}"/>"
     heading="{{ heading }}">

    <div ng-hide="empty || vulns || hasFilters()" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <%@ include file="actionButtons.jspf" %>

    <div ng-show="showTypeSelect" class="btn-group">
        <button type="button" class="btn" ng-model="vulnType" btn-radio="'Open'">{{ numOpen }} Open</button>
        <button ng-show="numClosed > 0" type="button" class="btn" ng-model="vulnType" btn-radio="'Closed'">{{ numClosed }} Closed</button>
        <button ng-show="numFalsePositive > 0" type="button" class="btn" ng-model="vulnType" btn-radio="'False Positive'">{{ numFalsePositive }} False Positive</button>
        <button ng-show="numHidden > 0" type="button" class="btn" ng-model="vulnType" btn-radio="'Hidden'">{{ numHidden }} Hidden</button>
    </div>

    <span ng-show="vulns && loading" style="float:right" class="spinner dark"></span>

    <%@ include file="filter.jspf" %>

    <div ng-show="empty && !filtered" class="empty-tab-drop-area">
        <div>Drop a scan here to upload.</div>
    </div>

    <div ng-show="empty && filtered" class="alert alert-danger">
        These filters found 0 results.
    </div>

    <div ng-show="vulns">
        <div class="pagination no-margin" ng-show="numVulns > 100" >
            <pagination class="no-margin" total-items="numVulns / 10" max-size="5" page="page"></pagination>

            <input  ng-enter="goToPage()" style="width:50px" type="number" ng-model="pageInput"/>
            <button class="btn" ng-click="goToPage()"> Go to Page </button>
        </div>

        <table class="table sortable table-hover tf-colors" style="table-layout: fixed;" id="anyid">
            <thead>
                <tr>
                    <c:if test="${ (not hideCheckboxes) and (canModifyVulnerabilities || canSubmitDefects) }">
                        <th style="width:12px" class="first unsortable"><input type="checkbox" id="chkSelectAll" ng-model="allSelected" ng-click="toggleAll()"></th>
                    </c:if>
                    <th style="width:8px;"></th>
                    <th style="width:64px" class="pointer" ng-click="setSort('Severity')">
                        Severity<span id="headerCaret2"
                                      class="caret-down"
                                      ng-class="{ expanded: sortType === 'Severity'}"></span>
                    </th>
                    <th style="width:260px" class="pointer" ng-click="setSort('Type')">
                        Type<span id="headerCaret1"
                                  class="caret-down"
                                  ng-class="{ expanded: sortType === 'Type'}"></span>
                    </th>
                    <th style="width:220px" class="pointer" ng-click="setSort('Path')">
                        Path<span id="headerCaret3"
                                  class="caret-down"
                                  ng-class="{ expanded: sortType === 'Path'}"></span>
                    </th>
                    <th class="pointer" style="width:90px;" ng-click="setSort('Parameter')">
                        Parameter<span id="headerCaret4"
                                       class="caret-down"
                                       ng-class="{ expanded: sortType === 'Parameter'}"></span>
                    </th>
                    <th style="width:24px;"></th>
                    <th ng-show="application.defectTracker" style="width:24px;"></th>
                    <th style="width:65px;"></th>
                </tr>
            </thead>
            <tbody>
                <tr ng-repeat-start="vuln in vulns" class="bodyRow pointer" ng-class="{
                        error: vuln.severityName === 'Critical',
                        warning: vuln.severityName === 'High',
                        success: vuln.severityName === 'Medium',
                        info: vuln.severityName === 'Info' || vuln.severityName === 'Low'
                        }">
                    <c:if test="${ (not hideCheckboxes) and (canModifyVulnerabilities || canSubmitDefects) }">
                        <td style="width:12px">
                            <input class="vulnIdCheckbox" id="vulnerabilityIds{{ index }}" ng-click="setCheckedAll(vuln.checked)" type="checkbox" ng-model="vuln.checked">
                            <input class="vulnIdCheckboxHidden" type="hidden" value="on" name="_vulnerabilityIds">
                        </td>
                    </c:if>
                    <td ng-click="expand(vuln)" class="pointer">
                        <span ng-class="{ expanded: vuln.expanded }" id="caret{{ vuln.id }}" class="caret-right"></span>
                    </td>
                    <td ng-click="expand(vuln)" class="pointer" id="severity{{ $index }}"> {{ vuln.severityName }} </td>
                    <td ng-click="expand(vuln)" class="pointer" id="type{{ $index }}">
                        {{ vuln.vulnerabilityName }}
                    </td>

                    <!-- TODO dependencies -->
                    <td ng-click="expand(vuln)" class="pointer" style="word-wrap: break-word; width:100px" id="path{{ $index }}"> {{ vuln.path }} </td>
                    <td ng-click="expand(vuln)" class="pointer" id="parameter{{ $index }}"> {{ vuln.parameter }} </td>
                    <%--<c:if test="${ not empty vulnerability.originalFinding.dependency }">--%>
                        <%--<td class="pointer" colspan="2">--%>
                            <%--<c:out value="${ vulnerability.originalFinding.dependency.cve } "/>--%>
                            <%--(<a target="_blank" id="cve{{ $index }}" href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=${ vulnerability.originalFinding.dependency.cve }">View</a>)--%>
                        <%--</td>--%>
                    <%--</c:if>--%>

                    <td ng-show="application.defectTracker">
                        <div ng-show="vuln.defect" class="tooltip-container" data-placement="left" ng-attr-title="{{ vuln.defect.nativeId }} ({{ vuln.defect.status }})" style="width:100%;text-align:right;">
                            <a id="bugLink{{ $index }}" target="_blank" ng-href="{{ vuln.defect.defectURL }}">
                                <img ng-src="<%=request.getContextPath()%>/images/{{ vuln.defect.bugImageName }}" class="transparent_png" alt="Threadfix"/>
                            </a>
                        </div>
                    </td>
                    <td ng-click="expand(vuln)" class="expandableTrigger">
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
                                <div class="vuln-table-box" id="commentDiv{{ vuln.id }}" style="width:450px;margin-bottom:10px;">
                                    <%@ include file="/WEB-INF/views/applications/vulnComments.jsp" %>
                                </div>
                                <br>
                                <a class="btn margin-bottom" ng-click="showCommentForm(vuln)">Add Comment</a>
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

    <%@ include file="actionButtons.jspf" %>

</tab>

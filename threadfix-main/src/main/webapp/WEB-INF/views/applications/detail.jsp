<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/></title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/applicationDetailPageController.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/vulnTableController.js"></script>
</head>

<body id="apps">

    <!-- Get the CSRF token so we can use it everywhere -->
    <spring:url value="" var="emptyUrl"/>
    <div ng-controller="ApplicationDetailPageController" ng-init="csrfToken = '<c:out value="${ emptyUrl }"/>'">
        <spring:url value="{appId}/edit" var="editUrl">
            <spring:param name="appId" value="${ application.id }"/>
        </spring:url>
        <spring:url value="{appId}/delete" var="deleteUrl">
            <spring:param name="appId" value="${ application.id }"/>
        </spring:url>
        <spring:url value="{appId}/progress/{numScans}" var="dataRefreshUrl">
            <spring:param name="appId" value="${ application.id }"/>
            <spring:param name="numScans" value="${ numScansBeforeUpload }"/>
        </spring:url>

        <div id="headerDiv"
                data-wait-for-refresh="<c:out value="${ checkForRefresh }"/>"
                data-refresh-url="<c:out value="${ dataRefreshUrl }"/>">
            <%@ include file="/WEB-INF/views/applications/detailHeader.jsp" %>
        </div>

        <div id="addWafSuccessMessage" style="display:none" class="alert alert-success">
            <button class="close" type="button">x</button>
            The WAF <span id="wafName"></span> has been added to the Application.
        </div>

        <div id="addDefectTrackerSuccessMessage" style="display:none" class="alert alert-success">
            <button class="close" type="button">x</button>
            The Defect Tracker <span id="defectTrackerName"></span> has been added to the Application.
        </div>

        <div style="padding-top:10px;" id="helpText">
            Applications are used to store, unify, and manipulate scan results from security scanners.
            <c:if test="${ empty application.scans }">
                <br/><br/>To get started, click Upload Scan to start uploading security scans.
            </c:if>
        </div>

        <c:if test="${ canGenerateReports }">
            <div class="container-fluid">
                <div class="row-fluid">
                    <div class="span6">
                        <h4>
                            6 Month Vulnerability Burndown
                            <c:if test="${ numVulns > 0 }">
                                <spring:url value="/reports/9/{orgId}/{appId}" var="reportsUrl">
                                    <spring:param name="orgId" value="${ application.organization.id }"/>
                                    <spring:param name="appId" value="${ application.id }"/>
                                </spring:url>
                                <span style="font-size:12px;float:right;">
                                    <a id="leftViewMore" style="display:none" href="<c:out value="${ reportsUrl }"/>">View More</a>
                                </span>
                            </c:if>
                        </h4>
                        <c:if test="${ numVulns > 0 }">
                            <spring:url value="/dashboard/leftReport" var="reportsUrl"/>
                            <form id="leftReportForm" action="<c:out value="${ reportsUrl }"/>">
                                <input style="display:none" name="orgId" value="<c:out value="${ application.organization.id }"/>"/>
                                <input style="display:none" name="appId" value="<c:out value="${ application.id }"/>"/>
                            </form>
                            <div id="leftTileReport">
                                <%@ include file="/WEB-INF/views/reports/loading.jspf" %>
                            </div>
                        </c:if>
                        <c:if test="${ numVulns == 0 }">
                            <%@ include file="/WEB-INF/views/reports/emptyReport.jspf" %>
                        </c:if>
                    </div>

                     <div class="span6">
                        <h4>
                            Top 10 Vulnerabilities
                            <c:if test="${ numVulns > 0 }">
                                <spring:url value="/reports/3/{orgId}/{appId}" var="reportsUrl">
                                    <spring:param name="orgId" value="${ application.organization.id }"/>
                                    <spring:param name="appId" value="${ application.id }"/>
                                </spring:url>
                                <span style="font-size:12px;float:right;">
                                    <a id="rightViewMore" style="display:none" href="<c:out value="${ reportsUrl }"/>">View More</a>
                                </span>
                            </c:if>
                        </h4>
                        <c:if test="${ numVulns > 0 }">
                            <spring:url value="/dashboard/rightReport" var="reportsUrl"/>
                            <form id="rightReportForm" action="<c:out value="${ reportsUrl }"/>">
                                <input style="display:none" name="orgId" value="<c:out value="${ application.organization.id }"/>"/>
                                <input style="display:none" name="appId" value="<c:out value="${ application.id }"/>"/>
                            </form>
                            <div id="rightTileReport">
                                <%@ include file="/WEB-INF/views/reports/loading.jspf" %>
                            </div>
                        </c:if>
                        <c:if test="${ numVulns == 0 }">
                            <%@ include file="/WEB-INF/views/reports/emptyReport.jspf" %>
                        </c:if>
                    </div>
                </div>
            </div>
        </c:if>

            <spring:url value="/organizations/{orgId}/applications/{appId}/vulnTab" var="vulnTabUrl">
                <spring:param name="orgId" value="${ application.organization.id }"/>
                <spring:param name="appId" value="${ application.id }"/>
            </spring:url>
            <spring:url value="/organizations/{orgId}/applications/{appId}/scanTab" var="scanTabUrl">
                <spring:param name="orgId" value="${ application.organization.id }"/>
                <spring:param name="appId" value="${ application.id }"/>
            </spring:url>
            <spring:url value="/organizations/{orgId}/applications/{appId}/closedTab" var="closedTabUrl">
                <spring:param name="orgId" value="${ application.organization.id }"/>
                <spring:param name="appId" value="${ application.id }"/>
            </spring:url>
            <spring:url value="/organizations/{orgId}/applications/{appId}/falsePositiveTab" var="falsePositiveTabUrl">
                <spring:param name="orgId" value="${ application.organization.id }"/>
                <spring:param name="appId" value="${ application.id }"/>
            </spring:url>
            <spring:url value="/organizations/{orgId}/applications/{appId}/docsTab" var="docsTabUrl">
                <spring:param name="orgId" value="${ application.organization.id }"/>
                <spring:param name="appId" value="${ application.id }"/>
            </spring:url>
            <spring:url value="/organizations/{orgId}/applications/{appId}/hiddenTab" var="hiddenTabUrl">
                <spring:param name="orgId" value="${ application.organization.id }"/>
                <spring:param name="appId" value="${ application.id }"/>
            </spring:url>
            <spring:url value="/organizations/{orgId}/applications/{appId}/scanQueueTab" var="scanQueueTabUrl">
                <spring:param name="orgId" value="${ application.organization.id }"/>
                <spring:param name="appId" value="${ application.id }"/>
            </spring:url>
            <spring:url value="/organizations/{orgId}/applications/{appId}/scheduledScanTab" var="scheduledScanTabUrl">
                <spring:param name="orgId" value="${ application.organization.id }"/>
                <spring:param name="appId" value="${ application.id }"/>
            </spring:url>
            <br>

        <!-- TODO Fix the active tab stuff -->
        <%--<c:choose>--%>
            <%--<c:when test="${activeTab == 'scan_tab'}"><c:set var="scanTab" value="active" /></c:when>--%>
            <%--<c:when test="${activeTab == 'file_tab'}"><c:set var="fileTab" value="active" /></c:when>--%>
            <%--<c:when test="${activeTab == 'scan_agent_task_tab'}"><c:set var="scanAgentTaskTab" value="active" /></c:when>--%>
            <%--<c:when test="${activeTab == 'scheduled_scan_tab'}"><c:set var="scheduledScanTab" value="active" /></c:when>--%>
            <%--<c:when test="${activeTab == 'closed_vuln_tab'}"><c:set var="closedVulnTab" value="active" /></c:when>--%>
            <%--<c:when test="${activeTab == 'false_positive_tab'}"><c:set var="falsePositiveTab" value="active" /></c:when>--%>
            <%--<c:otherwise><c:set var="activeVulnTab" value="active" /></c:otherwise>--%>
        <%--</c:choose>--%>

        <tabset>
            <tab heading="
            ${ fn:escapeXml(numVulns) }
                        <c:if test="${ numVulns == 1 }">Vulnerability</c:if>
                        <c:if test="${ numVulns != 1 }">Vulnerabilities</c:if>
            ">
                <%@ include file="/WEB-INF/views/applications/tabs/vulnTab.jsp" %>
            </tab>
            <tab heading="
                ${ fn:length(application.scans) }
                        <c:if test="${ fn:length(application.scans) == 1 }">Scan</c:if>
                        <c:if test="${ fn:length(application.scans) != 1 }">Scans</c:if>
            ">
                <%@ include file="/WEB-INF/views/applications/tabs/scanTab.jsp" %>
            </tab>
            <tab heading="
                ${ fn:length(application.scans) }
                        <c:if test="${ fn:length(application.scans) == 1 }">File</c:if>
                        <c:if test="${ fn:length(application.scans) != 1 }">Files</c:if>
            ">
                <%@ include file="/WEB-INF/views/applications/tabs/scanTab.jsp" %>
            </tab>
            <tab heading="
                ${ fn:length(application.scans) }
                        <c:if test="${ fn:length(application.scans) == 1 }">Scan Agent Task</c:if>
                        <c:if test="${ fn:length(application.scans) != 1 }">Scan Agent Tasks</c:if>
            ">
                <%@ include file="/WEB-INF/views/applications/tabs/scanTab.jsp" %>
            </tab>
            <tab heading="
                ${ fn:length(application.scans) }
                        <c:if test="${ fn:length(application.scans) == 1 }">Scheduled Scan</c:if>
                        <c:if test="${ fn:length(application.scans) != 1 }">Scheduled Scans</c:if>
            ">
                <%@ include file="/WEB-INF/views/applications/tabs/scanTab.jsp" %>
            </tab>
        </tabset>

        <%--<div id="addWaf" class="modal hide fade" tabindex="-1"--%>
                <%--role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">--%>
            <%--<%@ include file="/WEB-INF/views/applications/forms/addWafForm.jsp" %>--%>
        <%--</div>--%>

        <%--<div id="createWaf" class="modal hide fade" tabindex="-1"--%>
                <%--role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">--%>
            <%--<%@ include file="/WEB-INF/views/wafs/forms/createWafForm.jsp" %>--%>
        <%--</div>--%>

        <%--<div id="addDefectTracker" class="modal hide fade" tabindex="-1"--%>
            <%--role="dialog" aria-labelledby="myModalLabel" aria-hidden="true" style="width:600px;">--%>
            <%--<%@ include file="/WEB-INF/views/applications/forms/addDTForm.jsp" %>--%>
        <%--</div>--%>

        <%--<%@ include file="/WEB-INF/views/config/defecttrackers/modals/createDTModal.jsp" %>--%>
        <%--<%@ include file="/WEB-INF/views/defects/submitDefectModal.jsp" %>--%>
        <%--<%@ include file="/WEB-INF/views/defects/mergeDefectModal.jsp" %>--%>

    </div>
</body>
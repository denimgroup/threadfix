<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/></title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/applicationDetailPageController.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/applicationPageModalController.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/vulnTableController.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/reportsController.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/modalControllerWithConfig.js"></script>
</head>

<body id="apps">

    <!-- Get the CSRF token so we can use it everywhere -->
    <spring:url value="" var="emptyUrl"/>
    <div ng-controller="ApplicationDetailPageController" ng-init="csrfToken = '<c:out value="${ emptyUrl }"/>'">

        <%@ include file="/WEB-INF/views/applications/forms/addWafForm.jsp" %>
        <%@ include file="/WEB-INF/views/wafs/forms/createWafForm.jsp" %>
        <%--<%@ include file="/WEB-INF/views/applications/forms/addDTForm.jsp" %>--%>
        <%--<%@ include file="/WEB-INF/views/config/defecttrackers/modals/createDTModal.jsp" %>--%>
        <%--<%@ include file="/WEB-INF/views/defects/submitDefectModal.jsp" %>--%>
        <%--<%@ include file="/WEB-INF/views/defects/mergeDefectModal.jsp" %>--%>

        <div id="headerDiv">
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

        <div ng-controller="ReportsController" ng-init="csrfToken = '<c:out value="${ emptyUrl }"/>'" class="container-fluid">
            <c:if test="${ canGenerateReports }">
                <div class="row-fluid">
                    <div class="span6">
                        <spring:url value="/reports/9" var="reportsUrl"/>
                        <h4>6 Month Vulnerability Burndown<span style="font-size:12px;float:right;">
                            <a id="leftViewMore" href="<c:out value="${ reportsUrl }"/>">View More</a></span>
                        </h4>
                        <div id="leftTileReport">
                            <div ng-show="leftReport" bind-html-unsafe="leftReport" class="tableReportDiv report-image"></div>
                            <div ng-hide="leftReport || leftReportFailed" class="team-report-wrapper report-image">
                                <div style="float:right;padding-top:120px" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>
                            </div>
                            <div ng-show="leftReportFailed" class="team-report-wrapper report-image">
                                <div style="text-align: center; padding-top:120px;">
                                    Report Failed
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="span6">
                        <spring:url value="/reports/10" var="reportsUrl"/>
                        <h4>Top 10 Vulnerabilities<span style="font-size:12px;float:right;">
                            <a id="rightViewMore" href="<c:out value="${ reportsUrl }"/>">View More</a></span>
                        </h4>
                        <div id="rightTileReport">
                            <div ng-show="rightReport" bind-html-unsafe="rightReport" class="tableReportDiv report-image"></div>
                            <div ng-hide="rightReport || rightReportFailed" class="team-report-wrapper report-image">
                                <div style="float:right;padding-top:120px" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>
                            </div>
                            <div ng-show="rightReportFailed" class="team-report-wrapper report-image">
                                <div style="text-align: center; padding-top:120px;">
                                    Report Failed
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </c:if>
        </div>

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

        <tabset style="margin-top:10px;">
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
                ${ fn:length(application.documents) }
                        <c:if test="${ fn:length(application.documents) == 1 }">File</c:if>
                        <c:if test="${ fn:length(application.documents) != 1 }">Files</c:if>
            ">
                <%@ include file="/WEB-INF/views/applications/tabs/docsTab.jsp" %>
            </tab>
            <c:if test="${isEnterprise}">
                <tab heading="
                    ${ fn:length(application.scans) }
                            <c:if test="${ fn:length(application.scans) == 1 }">Scan Agent Task</c:if>
                            <c:if test="${ fn:length(application.scans) != 1 }">Scan Agent Tasks</c:if>
                ">
                    <%@ include file="/WEB-INF/views/applications/tabs/scanQueueTab.jsp" %>
                </tab>
                <tab heading="
                    ${ fn:length(application.scans) }
                            <c:if test="${ fn:length(application.scans) == 1 }">Scheduled Scan</c:if>
                            <c:if test="${ fn:length(application.scans) != 1 }">Scheduled Scans</c:if>
                ">
                    <%@ include file="/WEB-INF/views/applications/tabs/scheduledScanTab.jsp" %>
                </tab>
            </c:if>
        </tabset>


    </div>
</body>
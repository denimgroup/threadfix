<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/></title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/application-detail-page-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/application-page-modal-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/vuln-table-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/reports-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/upload-scan-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/modal-controller-with-config.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/add-defect-tracker-modal-controller.js"></script>
</head>

<!-- Get the CSRF token so we can use it everywhere -->
<spring:url value="" var="emptyUrl"/>
<body ng-controller="ApplicationDetailPageController"
      ng-init="csrfToken = '<c:out value="${ emptyUrl }"/>';
         empty = <c:out value="${ numVulns }"/> === 0"
      ng-file-drop="onFileSelect($files)"
      id="apps">

    <div class="uploadable" style="padding-top:300px"><div style="opacity:1">Drop files anywhere to upload.</div></div>
    <div>

        <%@ include file="forms/uploadScanForm.jsp"%>
        <%@ include file="/WEB-INF/views/applications/forms/addWafForm.jsp" %>
        <%@ include file="/WEB-INF/views/wafs/forms/createWafForm.jsp" %>
        <%@ include file="/WEB-INF/views/applications/forms/addDTForm.jsp" %>
        <%@ include file="/WEB-INF/views/config/defecttrackers/modals/createDTModal.jsp" %>
        <%--<%@ include file="/WEB-INF/views/defects/submitDefectModal.jsp" %>--%>
        <%--<%@ include file="/WEB-INF/views/defects/mergeDefectModal.jsp" %>--%>

        <div id="headerDiv">
            <%@ include file="/WEB-INF/views/applications/detailHeader.jsp" %>
        </div>

        <div style="padding-top:10px;" id="helpText">
            Applications are used to store, unify, and manipulate scan results from security scanners.
            <c:if test="${ empty application.scans }">
                <br/><br/>To get started, click Upload Scan to start uploading security scans.
            </c:if>
        </div>

        <div class="container-fluid">
            <%@include file="reports.jspf"%>
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
            <%@ include file="/WEB-INF/views/applications/tabs/vulnTab.jsp" %>
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
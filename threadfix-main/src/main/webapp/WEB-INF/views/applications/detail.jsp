<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/></title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/add-defect-tracker-modal-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/application-detail-page-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/application-page-modal-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/defect-submission-modal-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/modal-controller-with-config.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/reports-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/scan-table-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/upload-scan-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/scheduled-scan-tab-controller.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/vuln-table-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/document-form-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/scan-agent-tasks-tab-controller.js"></script>
</head>

<body ng-controller="ApplicationDetailPageController"
      ng-init="empty = <c:out value="${ numVulns }"/> === 0"
      ng-file-drop="onFileSelect($files)"
      ng-class="{ 'drag-enabled': dragEnabled }"
      id="apps">

    <%@ include file="/WEB-INF/views/angular-init.jspf"%>

    <div class="uploadable" style="padding-top:300px"><div style="opacity:1">Drop files anywhere to upload.</div></div>
    <div>

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

        <tabset style="margin-top:10px;">
            <%@ include file="/WEB-INF/views/applications/tabs/vulnTab.jsp" %>
            <%@ include file="/WEB-INF/views/applications/tabs/scanTab.jsp" %>
            <%@ include file="/WEB-INF/views/applications/tabs/docsTab.jsp" %>
            <c:if test="${isEnterprise}">
                <tab ng-controller="ScanAgentTasksTabController" heading="{{ heading }}">
                    <!-- TODO refactor this nesting -->
                    <c:if test="${ canManageApplications }">
                        <div style="margin-top:10px;margin-bottom:7px;">
                            <a id="addScanQueueLink" class="btn" ng-click="openNewScanAgentTaskModal()">Add New Task</a>
                        </div>
                    </c:if>

                    <%@ include file="/WEB-INF/views/applications/tabs/scanQueueTab.jsp" %>
                </tab>
                <tab ng-controller="ScheduledScanTabController" heading="{{ heading }}">
                    <%@ include file="/WEB-INF/views/applications/tabs/scheduledScanTab.jsp" %>
                </tab>
            </c:if>
        </tabset>


    </div>

    <%@ include file="forms/uploadScanForm.jsp"%>
    <%@ include file="/WEB-INF/views/applications/forms/addWafForm.jsp" %>
    <%@ include file="/WEB-INF/views/wafs/forms/createWafForm.jsp" %>
    <%@ include file="/WEB-INF/views/applications/forms/addDTForm.jsp" %>
    <%@ include file="/WEB-INF/views/config/defecttrackers/modals/createDTModal.jsp" %>
    <%@ include file="/WEB-INF/views/defects/submitDefectForm.jsp" %>
    <%@ include file="/WEB-INF/views/defects/mergeDefectForm.jsp" %>
    <%@ include file="/WEB-INF/views/applications/forms/vulnCommentForm.jsp"%>
    <%@ include file="/WEB-INF/views/applications/forms/uploadDocForm.jsp"%>
    <%@ include file="/WEB-INF/views/applications/forms/manualFindingForm.jsp"%>
    <%@ include file="/WEB-INF/views/applications/forms/addScheduledScanForm.jsp"%>
    <%@ include file="/WEB-INF/views/applications/forms/addScanQueueForm.jsp" %>
</body>
<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Defect Trackers</title>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/scheduled-defect-tracker-update-tab-controller.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/defect-trackers-tab-controller.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/modal-controller-with-config.js"></script>
</head>

<body id="config">
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <tabset>
        <%@include file="/WEB-INF/views/config/defecttrackers/tabs/defectTrackersTab.jsp"%>
        <%@include file="/WEB-INF/views/config/defecttrackers/tabs/scheduledUpdateTab.jsp"%>
    </tabset>
    <%@ include file="/WEB-INF/views/applications/forms/addScheduledDefectTrackerUpdateForm.jsp"%>
</body>
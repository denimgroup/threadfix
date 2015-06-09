<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Defect Trackers</title>
    <cbs:cachebustscript src="/scripts/scheduled-defect-tracker-update-tab-controller.js"/>
    <cbs:cachebustscript src="/scripts/defect-trackers-tab-controller.js"/>
    <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
    <cbs:cachebustscript src="/scripts/update-defect-defaults-modal-controller.js"/>
    <cbs:cachebustscript src="/scripts/default-value-mapping.js"/>
</head>

<body id="config">
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <tabset>
        <%@include file="/WEB-INF/views/config/defecttrackers/tabs/defectTrackersTab.jsp"%>
        <%@include file="/WEB-INF/views/config/defecttrackers/tabs/scheduledUpdateTab.jsp"%>
    </tabset>


    <script type="text/ng-template" id="newScheduledUpdate.html">
        <%@ include file="/WEB-INF/views/applications/forms/addScheduledJobForm.jsp"%>
    </script>
</body>
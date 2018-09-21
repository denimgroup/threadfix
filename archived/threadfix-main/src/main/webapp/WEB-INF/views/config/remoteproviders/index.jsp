<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Remote Providers</title>
	<cbs:cachebustscript src="/scripts/remote-providers-tab-controller.js"/>
	<cbs:cachebustscript src="/scripts/scheduled-remote-provider-import-tab-controller.js"/>
	<cbs:cachebustscript src="/scripts/remote-provider-modal-controller.js"/>
	<cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
    <cbs:cachebustscript src="/scripts/remote-provider-modal-mapping-controller.js"/>
</head>

<body>
    <tabset>
        <%@ include file="/WEB-INF/views/config/remoteproviders/tabs/remoteProvidersTab.jsp" %>
        <%@ include file="/WEB-INF/views/config/remoteproviders/tabs/scheduledImportTab.jsp" %>
    </tabset>

    <script type="text/ng-template" id="newScheduledImport.html">
        <%@ include file="/WEB-INF/views/applications/forms/addScheduledJobForm.jsp"%>
    </script>
</body>

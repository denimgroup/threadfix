<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Remote Providers</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-providers-tab-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/scheduled-remote-provider-import-tab-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-provider-modal-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/modal-controller-with-config.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-provider-modal-mapping-controller.js"></script>
</head>

<body>
    <tabset>
        <%@ include file="/WEB-INF/views/config/remoteproviders/tabs/remoteProvidersTab.jsp" %>
        <%@ include file="/WEB-INF/views/config/remoteproviders/tabs/scheduledImportTab.jsp" %>
    </tabset>

    <%@ include file="/WEB-INF/views/applications/forms/addScheduledRemoteProviderImportForm.jsp"%>
</body>

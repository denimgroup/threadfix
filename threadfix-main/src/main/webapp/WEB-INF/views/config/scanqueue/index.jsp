<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Scan Agent Tasks</title>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/scan-agent-tasks-index-controller.js"></script>
</head>

<body ng-controller="ScanAgentTasksIndexController">
	<h2>Scan Agent Tasks</h2>

    <%@ include file="/WEB-INF/views/angular-init.jspf" %>

    <c:if test="${ not empty successMessage }">
        <div class="alert alert-success" ng-hide="hidden">
            <button class="close" ng-click="hidden = true" type="button">&times;</button>
            <c:out value="${ successMessage }"/>
        </div>
    </c:if>

    <%@ include file="/WEB-INF/views/errorMessage.jsp"%>
    <%@ include file="/WEB-INF/views/successMessage.jspf"%>

	<div id="helpText">
		The scan queue is a list of scans ThreadFix has been asked to coordinate.<br/>
	</div>

    <%@ include file="/WEB-INF/views/config/scanqueue/scanQueueTable.jsp" %>

</body>
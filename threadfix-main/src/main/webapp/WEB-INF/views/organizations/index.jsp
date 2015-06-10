<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Applications</title>
	<cbs:cachebustscript src="/scripts/applications-index-controller.js"/>
	<cbs:cachebustscript src="/scripts/upload-scan-controller.js"/>
    <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
    <cbs:cachebustscript src="/scripts/report/vuln-summary-modal-controller.js"/>
</head>

<body id="apps">
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <%@ include file="/WEB-INF/views/reports/vulnSummaryModal.jsp"%>

	<h2>Teams</h2>

    <div ng-controller="ApplicationsIndexController" ng-init="successMessage = '<c:out value="${ successMessage }"/>'">

        <security:authorize ifNotGranted="ROLE_CAN_MANAGE_TEAMS">
            <div ng-show="teams && teams.length === 0" class="alert alert-error">
                You don't have permission to access any ThreadFix applications or to create one for yourself.
                Contact your administrator to get help.
            </div>
        </security:authorize>

        <div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

        <%@ include file="/WEB-INF/views/successMessage.jspf" %>

        <div ng-show="errorMessage" class="alert alert-success">
            <button class="close" data-dismiss="errorMessage = false" type="button">&times;</button>
            {{ errorMessage }}
        </div>

        <%@ include file="/WEB-INF/views/organizations/indexTable.jsp" %>

    </div>

</body>

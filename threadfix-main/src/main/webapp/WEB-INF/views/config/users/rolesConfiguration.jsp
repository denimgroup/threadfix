<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Manage Users</title>
	<cbs:cachebustscript src="/scripts/user-permissions-config-controller.js"/>
	<cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
	<cbs:cachebustscript src="/scripts/permission-modal-controller.js"/>
</head>

<body id="config" ng-controller="UserPermissionsConfigController" ng-init="userId = <c:out value="${ user.id }"/>">

    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <%@ include file="/WEB-INF/views/config/users/permissionForm.jsp" %>

    <h2>Edit User <c:out value="${ user.name }"/> Permissions</h2>

    <%@ include file="/WEB-INF/views/successMessage.jspf" %>
    <%@ include file="/WEB-INF/views/errorMessage.jspf" %>

	<a id="addPermissionButton" class="btn" ng-click="openAddPermissionsModal()" ng-disabled="noTeams">
		Add Permissions
	</a>

	<div id="permsTableDiv">
		<%@ include file="/WEB-INF/views/config/users/permTable.jsp" %>
	</div>

</body>
	
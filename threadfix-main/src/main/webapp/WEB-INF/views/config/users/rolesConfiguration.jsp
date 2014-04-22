<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Manage Users</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/user-permissions-config-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/modal-controller-with-config.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/permission-modal-controller.js"></script>
</head>

<body id="config" ng-controller="UserPermissionsConfigController" ng-init="userId = <c:out value="${ user.id }"/>">

    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <%@ include file="/WEB-INF/views/config/users/permissionForm.jsp" %>

	<h2>Edit User <c:out value="${ user.name }"/> Permissions</h2>

	<a id="addPermissionButton" class="btn" ng-click="openAddPermissionsModal()">
		Add Permissions
	</a>

	<div id="permsTableDiv">
		<%@ include file="/WEB-INF/views/config/users/permTable.jsp" %>
	</div>

</body>
	
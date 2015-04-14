<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Manage Users</title>
	<cbs:cachebustscript src="/scripts/user-modal-controller.js"/>
	<cbs:cachebustscript src="/scripts/user-page-controller.js"/>
	<cbs:cachebustscript src="/scripts/user-permissions-config-controller.js"/>
	<cbs:cachebustscript src="/scripts/permission-modal-controller.js"/>

	<cbs:cachebustscript src="/scripts/roles-page-controller.js"/>
	<cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
	<cbs:cachebustscript src="/scripts/role-edit-modal-controller.js"/>
</head>

<body id="config" ng-controller="UserPageController" ng-init="rolesActive = 'roles' === '<c:out value="${ startingTab }"/>'">

    <%@ include file="/WEB-INF/views/angular-init.jspf"%>

	<tabset>
		<tab heading="Manage Users" select="rolesActive = false">
			<%@ include file="/WEB-INF/views/successMessage.jspf" %>
			<%@ include file="/WEB-INF/views/errorMessage.jsp" %>

			<div class="row">
				<div class="span3">
					<%@ include file="../common/userList.jspf" %>
				</div>
				<div class="span8">
					<%@ include file="../common/basicDetails.jspf" %>
					<%@ include file="rolesTables.jspf" %>
				</div>
			</div>
		</tab>
		<tab ng-controller="RolesPageController"
			 heading="Manage Roles"
			 active="rolesActive">
			<h2>Manage Roles</h2>

			<%@ include file="/WEB-INF/views/config/roles/form.jsp" %>
			<%@ include file="/WEB-INF/views/config/roles/newForm.jsp" %>

			<div id="helpText">
				ThreadFix Roles determine functional capabilities for associated users.<br/>
			</div>

			<%@ include file="/WEB-INF/views/successMessage.jspf" %>
			<%@ include file="/WEB-INF/views/errorMessage.jsp" %>

			<a id="createRoleModalLink" class="btn" ng-click="openNewRoleModal()">Create New Role</a>

			<div id="tableDiv">
				<%@ include file="/WEB-INF/views/config/roles/rolesTable.jsp" %>
			</div>
		</tab>
	</tabset>

</body>

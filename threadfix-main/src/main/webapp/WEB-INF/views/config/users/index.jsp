<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Manage Users</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/user-modal-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/user-page-controller.js"></script>
</head>

<spring:url value="" var="emptyUrl"/>
<body id="config" ng-controller="UserPageController" ng-init="csrfToken = '<c:out value="${ emptyUrl }"/>'">

	<h2>Manage Users</h2>
	
	<div id="helpText">
		Here you can create, edit, and delete users.
	</div>
	
	<%@ include file="/WEB-INF/views/successMessage.jspf" %>
	<%@ include file="/WEB-INF/views/errorMessage.jsp" %>
    <%@ include file="/WEB-INF/views/config/users/form.jsp" %>

    <div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <a id="newUserModalLink" class="btn" ng-click="openNewModal()">Add User</a>

	<table class="table table-striped">
		<thead>
			<tr>
				<th class="medium first">User</th>
				<th class="short">Edit / Delete</th>
				<security:authorize ifAnyGranted="ROLE_ENTERPRISE">
				    <th class="short">Edit Permissions</th>
				</security:authorize>
			</tr>
		</thead>
		<tbody id="userTableBody">
			<tr ng-repeat="user in users" class="bodyRow">
				<td id="name{{ user.name }}">
					{{ user.name }}
				</td>
				<td>
					<a id="editUserModal${ status.count }Link" class="btn" ng-click="openEditModal(user)">
						Edit / Delete
					</a>
				</td>
				<security:authorize ifAnyGranted="ROLE_ENTERPRISE">
				<td id="name${ status.count }">
					<spring:url value="/configuration/users/{userId}/permissions" var="editPermissionsUrl">
						<spring:param name="userId" value="${ user.id }"/>
					</spring:url>
					<a id="editPermissions${ status.count }" class="btn" href="${ fn:escapeXml(editPermissionsUrl) }">Edit Permissions</a>
				</td>
				</security:authorize>
			</tr>
		</tbody>
	</table>
</body>

<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Manage Users</title>
	<cbs:cachebustscript src="/scripts/user-modal-controller.js"/>
	<cbs:cachebustscript src="/scripts/user-page-controller.js"/>
</head>

<body id="config" ng-controller="UserPageController">

    <%@ include file="/WEB-INF/views/angular-init.jspf"%>

    <h2>Manage Users</h2>
	
	<div id="helpText">
		Here you can create, edit, and delete users.
	</div>

	<%@ include file="/WEB-INF/views/successMessage.jspf" %>
	<%@ include file="/WEB-INF/views/errorMessage.jsp" %>
    <%@ include file="/WEB-INF/views/config/users/form.jsp" %>
    <%@ include file="/WEB-INF/views/config/users/editForm.jsp" %>

    <div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <a id="newUserModalLink" class="btn" ng-click="openNewModal()">Add User</a>

	<div ng-show="countUsers > numberToShow" class="pagination" ng-init="page = 1">
		<pagination id="userPagination"
					class="no-margin"
					total-items="countUsers / numberToShow * 10"
					max-size="5"
					page="page"
					ng-model="page"
					ng-click="updatePage(page)"></pagination>
	</div>
	<br>

	<table class="table table-striped">
		<thead>
			<tr>
				<th class="medium first">Name</th>
				<th class="medium">Display Name</th>
				<th class="short">Edit / Delete</th>
				<security:authorize ifAnyGranted="ROLE_ENTERPRISE">
				    <th class="short">Edit Permissions</th>
				</security:authorize>
			</tr>
		</thead>
		<tbody id="userTableBody">
            <tr ng-hide="users || loading">
                <td colspan="3" style="text-align:center;">No Users found.</td>
            </tr>
			<tr ng-repeat="user in users" class="bodyRow">
				<td id="name{{ user.name }}">
					{{ user.name }}
				</td>
				<td id="displayName{{ user.displayName }}">
					{{ user.displayName }}
				</td>
				<td>
					<a id="editUserModal{{ user.name }}" class="btn" ng-click="openEditModal(user)">
						Edit / Delete
					</a>
				</td>
				<security:authorize ifAnyGranted="ROLE_ENTERPRISE">
				<td>
					<a id="editPermissions{{ user.name }}" class="btn" ng-click="goToEditPermissionsPage(user)">Edit Permissions</a>
				</td>
				</security:authorize>
			</tr>
		</tbody>
	</table>
</body>

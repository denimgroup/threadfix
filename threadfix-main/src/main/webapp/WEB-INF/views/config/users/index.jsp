<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Manage Users</title>
	<cbs:cachebustscript src="/scripts/user-modal-controller.js"/>
	<cbs:cachebustscript src="/scripts/user-page-controller.js"/>
	<cbs:cachebustscript src="/scripts/user-permissions-config-controller.js"/>
	<cbs:cachebustscript src="/scripts/permission-modal-controller.js"/>
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

	<div class="row">
		<div class="span3">
			<h4>User List <a id="newUserModalLink" class="btn" ng-click="openNewModal()">Create User</a></h4>

			<ul class="nav nav-pills">
				<li ng-repeat="user in users"
					id="lastYearReport"
					class="span2"
					ng-class="{ active: currentUser.id === user.id }">
					<a href="#" class="no-underline" ng-click="setCurrentUser(user)">{{ user.name }}</a>
				</li>
			</ul>

		</div>
		<div class="span8">
			<h4>Basic Details</h4>

			<div ng-hide="currentUser">No User Selected</div>

			<div ng-repeat="user in users" ng-if="user.wasSelected" ng-show="currentUser.id === user.id" class="user-page" ng-form="form">

				<div class="form-group">
					<label for="name">User</label>
					<input ng-model="currentUser.name" required type="text" name="name" id="name"/>
					<span id="name.errors.required" class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
					<span id="name.errors" class="errors" ng-show="user.name_error"> {{ user.name_error }}</span>
				</div>

				<div class="form-group">
					<label for="displayName">Display Name</label></td>
					<input ng-model="currentUser.displayName" type="text" name="displayName" id="displayName"/>
					<span id="displayName.errors" class="errors" ng-show="user.name_error"> {{ user.name_error }}</span>
				</div>

				<div class="form-group">
					<label for="password">Password</label></td>
					<input ng-disabled="currentUser.isLdapUser"
						   password-validate="{{ currentUser.passwordConfirm }}"
						   id="password"
						   ng-model="currentUser.unencryptedPassword"
						   type="password"
						   name="unencryptedPassword"
						   size="30"/>
					<span id="password.error.length" class="errors" ng-show="lengthRemaining">{{ lengthRemaining }} characters needed</span>
					<span id="password.error.match" class="errors" ng-show="form.unencryptedPassword.$dirty && form.unencryptedPassword.$error.matches">Passwords do not match.</span>
					<span id="password.error" class="errors" ng-show="user.password_error"> {{ user.password_error }}</span>
				</div>

				<div class="form-group">
					<label for="passwordConfirm">Confirm Password</label>
					<input ng-model="currentUser.passwordConfirm"
						   type="password"
						   ng-disabled="currentUser.isLdapUser"
						   style="margin-bottom:0"
						   id="passwordConfirm"
						   name="passwordConfirm"
						   size="30" />
				</div>

				<c:if test="${ ldap_plugin }">
					<div class="form-group">
						<label for="isLdapUserCheckbox">LDAP user</label>
						<input type="checkbox" class="ldapCheckbox"
							   id="isLdapUserCheckbox"
							   name="isLdapUser"
							   ng-model="currentUser.isLdapUser"/>
					</div>
				</c:if>

				<security:authorize ifAllGranted="ROLE_ENTERPRISE">

					<div class="form-group margin-top">
						<label for="roleSelect">Global Role</label>
						<select id="roleSelect" name="globalRole.id" ng-model="user.globalRole.id">
							<option ng-selected="!currentUser.globalRole.id" value="-1" label="No Global Access">No Global Access</option>
							<option ng-selected="role.id === 0" value="0" label="Read Access">Read Access</option>
							<option ng-selected="role.id === currentUser.globalRole.id" ng-repeat="role in roles" value="{{ role.id }}">
								{{ role.displayName }}
							</option>
						</select>
						<errors id="hasGlobalGroupAccessErrors" path="hasGlobalGroupAccess" cssClass="errors" />
					</div>
				</security:authorize>

				<div class="margin-top">
					<button id="loadingButton"
							disabled="disabled"
							class="btn btn-primary"
							ng-show="loading">
						<span class="spinner"></span>
						Submitting
					</button>
					<button id="submit"
							ng-class="{ disabled : !form.$dirty || form.$invalid || angular.equals(currentUser, user) }"
							class="btn btn-primary"
							ng-hide="loading"
							ng-click="submitUpdate(form.$valid)">Save Changes</button>
				</div>

				<security:authorize ifAllGranted="ROLE_ENTERPRISE">
					<div id="config">

						<%@ include file="/WEB-INF/views/config/users/permissionForm.jsp" %>

						<h4>
							Team Roles
							<a id="addPermissionButton" class="btn" ng-click="openAddTeamPermissionsModal()" ng-disabled="noTeams">
								Add Team Role
							</a>
						</h4>

						<table class="table">
							<thead>
								<th>Team</th>
								<th>Role</th>
							</thead>
							<tbody>
								<tr ng-repeat="map in currentUser.maps | filter:{ allApps : true }" class="bodyRow">
									<td id="teamName{{ map.organization.name }}all{{ map.role.displayName }}">{{ map.organization.name }}</td>
									<td id="roleName{{ map.organization.name }}all{{ map.role.displayName }}">
										{{ map.role.displayName }}
									</td>
									<td style="text-align:center">
										<a id="editAppMap{{ map.organization.name }}all{{ map.role.displayName }}" class="btn" ng-click="edit(map)">
											Edit
										</a>
									</td>
									<td style="text-align:center">
										<a class="btn" id="deleteAppMap{{ map.organization.name }}all{{ map.role.displayName }}" ng-click="deleteTeam(map)">
											Delete
										</a>
									</td>
								</tr>
							</tbody>
						</table>

						<h4>
							Application Roles
							<a id="addApplicationRoleButton" class="btn" ng-click="openAddApplicationPermissionsModal()">Add Application Role</a>
						</h4>

						<table class="table">
							<thead>
								<th>Team</th>
								<th>Application</th>
								<th>Role</th>
							</thead>
							<!-- This is a lot of watchers -->
							<tbody ng-repeat="map in currentUser.maps | filter:{ allApps : false }" style="border-top: 0">
								<tr ng-repeat="appMap in map.accessControlApplicationMaps" ng-show="!map.allApps && appMap.active" class="bodyRow">
									<td id="teamName{{ map.organization.name }}{{ appMap.application.name }}{{ appMap.role.displayName }}">
										{{ map.organization.name }}
									</td>
									<td id="applicationName{{ map.organization.name }}{{ appMap.application.name }}{{ appMap.role.displayName }}">
										{{ appMap.application.name }}
									</td>
									<td id="roleName{{ map.organization.name }}{{ appMap.application.name }}{{ appMap.role.displayName }}">
										{{ appMap.role.displayName }}
									</td>
									<td style="text-align:center">
										<a id="editAppMap{{ map.organization.name }}{{ appMap.application.name }}{{ appMap.role.displayName }}" class="btn" ng-click="edit(map)">
											Edit
										</a>
									</td>
									<td style="text-align:center">
										<a class="btn" id="deleteAppMap{{ map.organization.name }}{{ appMap.application.name }}{{ appMap.role.displayName }}" ng-click="deleteApp(appMap)">
											Delete
										</a>
									</td>
								</tr>
							</tbody>
						</table>
					</div>
				</security:authorize>
			</div>
		</div>
	</div>

	<table class="table table-striped" ng-hide="true">
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

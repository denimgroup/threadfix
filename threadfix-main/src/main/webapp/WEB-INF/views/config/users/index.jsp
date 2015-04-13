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
			<h4>User Details</h4>

			<div ng-hide="currentUser">No User Selected</div>

			<div ng-repeat="user in users" ng-if="user.wasSelected" ng-show="currentUser.id === user.id" class="form-group" ng-form="form">
				<table class="modal-form-table dataTable">
					<tbody>
					<tr>
						<td><label for="name">User</label></td>
						<td class="inputValue">
							<input ng-model="currentUser.name" required type="text" name="name" id="name"/>
							<span id="name.errors.required" class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
							<span id="name.errors" class="errors" ng-show="user.name_error"> {{ user.name_error }}</span>
						</td>
					</tr>
					<tr>
						<td><label for="displayName">Display Name</label></td>
						<td class="inputValue">
							<input ng-model="currentUser.displayName" type="text" name="displayName" id="displayName"/>
							<span id="displayName.errors" class="errors" ng-show="user.name_error"> {{ user.name_error }}</span>
						</td>
					</tr>
					<tr ng-if="!currentUser.isLdapUser">
						<td><label>Password</label></td>
						<td class="inputValue">
							<input password-validate="{{ currentUser.passwordConfirm }}" id="password" ng-model="currentUser.unencryptedPassword" type="password" id="passwordInput" name="unencryptedPassword" size="30"/>
							<span id="password.error.length" class="errors" ng-show="lengthRemaining">{{ lengthRemaining }} characters needed</span>
							<span id="password.error.match" class="errors" ng-show="form.unencryptedPassword.$dirty && form.unencryptedPassword.$error.matches">Passwords do not match.</span>
							<span id="password.error" class="errors" ng-show="user.password_error"> {{ user.password_error }}</span>
						</td>
					</tr>
					<tr ng-if="!currentUser.isLdapUser">
						<td><label>Confirm Password</label></td>
						<td class="inputValue">
							<input ng-model="currentUser.passwordConfirm" id="confirm" type="password" style="margin-bottom:0" id="passwordConfirmInput" name="passwordConfirm" size="30" />
						</td>
					</tr>
					<c:if test="${ ldap_plugin }">
						<tr>
							<td class="no-color"><label>LDAP user</label></td>
							<td class="no-color" style="text-align: left;">
								<input type="checkbox" class="ldapCheckbox"
									   id="isLdapUserCheckbox"
									   name="isLdapUser"
									   ng-model="currentUser.isLdapUser"/>
							</td>
						</tr>
					</c:if>
					<security:authorize ifAllGranted="ROLE_ENTERPRISE">
						<tr>
							<td class="no-color"><label>Global Access</label></td>
							<td class="no-color" style="text-align: left;">
								<input type="checkbox"
									   id="hasGlobalGroupAccessCheckbox"
									   class="globalAccessCheckBox"
									   name="hasGlobalGroupAccess"
									   ng-model="currentUser.hasGlobalGroupAccess"/>
							</td>
						</tr>
						<tr ng-show="currentUser.hasGlobalGroupAccess">
							<td class="no-color"><label>Global Role</label></td>
							<td class="no-color" style="text-align: left;">
								<select id="roleSelect" name="globalRole.id" ng-model="user.globalRole.id">
									<option value="0" label="Read Access">Read Access</option>
									<option ng-selected="role.id === currentUser.globalRole.id" ng-repeat="role in roles" value="{{ role.id }}">
										{{ role.displayName }}
									</option>
								</select>
							</td>
							<td class="no-color" style="border: 0 solid black; background-color: white; padding-left: 5px">
								<errors id="hasGlobalGroupAccessErrors" path="hasGlobalGroupAccess" cssClass="errors" />
							</td>
						</tr>
					</security:authorize>
					</tbody>
				</table>

				<br>
				<button id="loadingButton"
						disabled="disabled"
						class="btn btn-primary"
						ng-show="loading">
					<span class="spinner"></span>
					Submitting
				</button>
				<button id="submit"
						ng-class="{ disabled : !form.$dirty || form.$invalid }"
						class="btn btn-primary"
						ng-hide="loading"
						ng-click="submitUpdate(form.$valid)">Save Changes</button>
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

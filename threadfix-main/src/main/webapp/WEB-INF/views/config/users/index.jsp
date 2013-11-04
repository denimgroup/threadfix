<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Manage Users</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/user_page.js"></script>
</head>

<body id="config">
	<form:form modelAttribute="error" name="formErrors">
		<form:errors cssClass="errors" />
	</form:form>

	<h2>Manage Users</h2>
	
	<div id="helpText">
		Here you can create, edit, and delete users.
	</div>
	
	<%@ include file="/WEB-INF/views/successMessage.jspf" %>
	<%@ include file="/WEB-INF/views/errorMessage.jsp" %>
	
	<a id="newUserModalLink" href="#newUserModal" role="button" class="btn" data-toggle="modal">Add User</a>

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
		<c:forEach var="user" items="${ users }" varStatus="status">
			<tr class="bodyRow">
				<td id="name${ status.count }">
					<c:out value="${ user.name }"/>
				</td>
				<td>
					<a id="editUserModal${ status.count }Link" 
							href="#editUserModal${ user.id }" 
							role="button" 
							class="btn" 
							data-toggle="modal">
						Edit / Delete
					</a>
					<div id="editUserModal${ user.id }" class="modal hide fade" tabindex="-1"
							role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
						<%@ include file="/WEB-INF/views/config/users/editUserForm.jsp" %>
					</div>
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
		</c:forEach>
		</tbody>
	</table>
	
	<div id="newUserModal" class="modal hide fade" tabindex="-1"
			role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<%@ include file="/WEB-INF/views/config/users/newUserForm.jsp" %>
	</div>

</body>

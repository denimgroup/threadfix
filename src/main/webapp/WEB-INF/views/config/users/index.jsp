<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Manage Users</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/ajax_replace.js"></script>
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
	<%@ include file="/WEB-INF/views/errorMessage.jspf" %>

	<table class="table table-striped">
		<thead>
			<tr>
				<th class="medium first">User</th>
				<th class="short">Edit</th>
				<th class="short">Delete</th>
				<th class="short">Edit Permissions</th>
			</tr>
		</thead>
		<tbody id="userTableBody">
		<c:forEach var="user" items="${ users }" varStatus="status">
			<tr class="bodyRow">
				<td id="name${ status.count }">
					<c:out value="${ user.name }"/>
				</td>
				<td>
					<a id="editUserModal${ user.id }Link" href="#editUserModal${ user.id }" role="button" class="btn" data-toggle="modal">Edit</a>
					<div id="editUserModal${ user.id }" class="modal hide fade" tabindex="-1"
							role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
						<%@ include file="/WEB-INF/views/config/users/editUserForm.jsp" %>
					</div>
				</td>
				<td>
					<spring:url value="/configuration/users/{userId}/delete" var="deleteUrl">
						<spring:param name="userId" value="${ user.id }"/>
					</spring:url>
					<form id="command" method="POST" action="${ fn:escapeXml(deleteUrl) }">
					<c:choose>
						<c:when test="${ not user.isDeletable }">
							<input class="btn btn-danger" id="delete${ status.count }" type="submit" value="Delete" onclick="javascript:alert('You cannot delete this account because doing so would leave the system without users with the ability to manage either users or roles.'); return false;"/>
						</c:when>
						<c:when test="${ user.isThisUser }">
							<input class="btn btn-danger" id="delete${ status.count }" type="submit" value="Delete" onclick="return confirm('This is your account. Are you sure you want to remove yourself from the system?')"/>
						</c:when>
						<c:otherwise>
							<input class="btn btn-danger" id="delete${ status.count }" type="submit" value="Delete" onclick="return confirm('Are you sure you want to delete this User?')"/>
						</c:otherwise>
					</c:choose>
					</form>
				</td>
				<td id="name${ status.count }">
					<spring:url value="/configuration/users/{userId}/permissions" var="editPermissionsUrl">
						<spring:param name="userId" value="${ user.id }"/>
					</spring:url>
					<a class="btn" href="${ fn:escapeXml(editPermissionsUrl) }">Edit Permissions</a>
				</td>
			</tr>
		</c:forEach>
		</tbody>
	</table>
	
	<a id="newUserModalLink" href="#newUserModal" role="button" class="btn" data-toggle="modal">Add User</a>
	<div id="newUserModal" class="modal hide fade" tabindex="-1"
			role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<%@ include file="/WEB-INF/views/config/users/newUserForm.jsp" %>
	</div>

</body>

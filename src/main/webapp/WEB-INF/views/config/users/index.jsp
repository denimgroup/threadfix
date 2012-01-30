<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Manage Users</title>
</head>

<body id="config">
	<form:form modelAttribute="error" name="formErrors">
		<form:errors cssClass="errors" />
	</form:form>

	<h2>Manage Users</h2>
	
	<div id="helpText">
		Here you can create, edit, and delete users.
	</div>

	<table class="formattedTable">
		<thead>
			<tr>
				<th class="medium first">User</th>
				<th class="medium last">Role</th>
			</tr>
		</thead>
		<tbody id="userTableBody">
		<c:if test="${ empty userList }">
			<tr class="bodyRow">
				<td colspan="2" style="text-align:center;"> No users found.</td>
			</tr>
		</c:if>
		<c:forEach var="user" items="${ userList }">
			<tr class="bodyRow">
				<td>
					<spring:url value="users/{userId}" var="userUrl">
						<spring:param name="userId" value="${ user.id }" />
					</spring:url>
					<a href="${ fn:escapeXml(userUrl) }"><c:out value="${ user.name }"/></a>
				</td>
				<td><c:out value="${ user.role.displayName }"/></td>
			</tr>
		</c:forEach>
			<tr class="footer">
				<td class="first">
					<a id="addUserLink" href="<spring:url value="users/new" />">Add User</a>
				</td>
				<td colspan="1" class="last pagination" style="text-align:right"></td>
			</tr>
		</tbody>
	</table>
</body>
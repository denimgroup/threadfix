<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Roles</title>
</head>

<body>
	<h2>Roles</h2>
	
	<div id="helpText">
		ThreadFix Roles determine functional capabilities for associated users.<br/>
	</div>
	
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="medium first">Name</th>
				<th class="short">Edit</th>
				<th class="short">Delete</th>
				<th class="medium">Configure Users</th>
			</tr>
		</thead>
		<tbody>
			<c:if test="${ empty roleList }">
				<tr class="bodyRow">
					<td colspan="6" style="text-align:center;">No roles found.</td>
				</tr>
			</c:if>
			<c:forEach var="role" items="${ roleList }" varStatus="status">
				<tr class="bodyRow">
					<td id="role${ status.count }">
						<c:out value="${ role.displayName }"/>
					</td>
					<td>
						<spring:url value="/configuration/roles/{roleId}/edit" var="roleEditUrl">
							<spring:param name="roleId" value="${ role.id }" />
						</spring:url>
						<a id="edit${ status.count }" href="${ fn:escapeXml(roleEditUrl) }">Edit</a> 
					</td>
					<td>
						<spring:url value="/configuration/roles/{roleId}/delete" var="roleDeleteUrl">
							<spring:param name="roleId" value="${ role.id }" />
						</spring:url>
						<form:form method="POST" action="${ fn:escapeXml(roleDeleteUrl) }">
							<input id="delete${ status.count }" type="submit" 
							onclick="return confirm('Are you sure you want to delete this Role? All users will have their privileges revoked.')" 
							value="Delete"/>
						</form:form>
					</td>
					<td>
						<spring:url value="/configuration/roles/{roleId}/users" var="userConfigUrl">
							<spring:param name="roleId" value="${ role.id }" />
						</spring:url>
						<a id="userConfig${ status.count }" href="${ fn:escapeXml(userConfigUrl) }">Configure Users</a> 
					</td>
				</tr>
			</c:forEach>
		</tbody>
	</table>
	<br/>
	<a id="createNewroleLink" href="<spring:url value="/configuration/roles/new" />">Create New Role</a> |
	<a id="backToMenuLink" href="<spring:url value="/configuration" />">Back to Menu</a>
	
</body>

<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ user.name }"/></title>
</head>

<body id="config">
	<h2 id="nameText"><c:out value="${ user.name }"/></h2>
	
	<table class="dataTable">
		<tbody>
			<c:if test="${ empty roleString}">
				<tr class="bodyRow">
					<td class="label">Roles: </td>
					<td id="roleText" class="inputValue">No roles found.</td>
				</tr>
			</c:if>
			<c:if test="${ not empty roleString }">
			<tr>
				<td class="label">Roles: </td>
				<td id="roleText" class="inputValue">
					<c:out value="${ roleString}"/>
				</td>
			</tr>
			</c:if>
			<c:if test="${ empty groupString}">
				<tr class="bodyRow">
					<td class="label">Groups: </td>
					<td id="groupText" class="inputValue">No groups found.</td>
				</tr>
			</c:if>
			<c:if test="${ not empty groupString}">
			<tr>
				<td class="label">Groups: </td>
				<td id="groupText" class="inputValue">
					<c:out value="${ groupString }"/>
				</td>
			</tr>
			</c:if>
		</tbody>
	</table>
	<br />
	<spring:url value="{userId}/edit" var="editUrl">
		<spring:param name="userId" value="${ user.id }"/>
	</spring:url>
	<a id="editLink" href="${ fn:escapeXml(editUrl) }">Edit</a> | 
	
	<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_GROUPS">
		<spring:url value="{userId}/groups" htmlEscape="true" var="groupsUrl">
			<spring:param name="userId" value="${ user.id }"/>
		</spring:url>
		<a id="manageUsersLink" href="${ fn:escapeXml(groupsUrl) }">Configure Groups</a> |
	</security:authorize>
	
	<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_ROLES">
		<spring:url value="{userId}/roles" htmlEscape="true" var="rolesUrl">
			<spring:param name="userId" value="${ user.id }"/>
		</spring:url>
		<a id="manageUsersLink" href="${ fn:escapeXml(rolesUrl) }">Configure Roles</a> |
	</security:authorize>
	
	<spring:url value="{userId}/delete" var="deleteUrl">
		<spring:param name="userId" value="${ user.id }"/>
	</spring:url>
	
	<c:choose>
		<c:when test="${ lastUser }">
			<a id="deleteLink" href="javascript:alert('You cannot delete this account because doing so would leave the system without users with the ability to manage either users, groups, or roles.')">Delete</a> | 
		</c:when>
		<c:when test="${ isThisUser }">
			<a id="deleteLink" href="${ fn:escapeXml(deleteUrl) }" onclick="return confirm('This is your account. Are you sure you want to remove yourself from the system?')">Delete</a> | 
		</c:when>
		<c:otherwise>
			<a id="deleteLink" href="${ fn:escapeXml(deleteUrl) }" onclick="return confirm('Are you sure you want to delete this User?')">Delete</a> | 
		</c:otherwise>
	</c:choose>

	<a id="backToListLink" href="<spring:url value="/configuration/users" />">Back to Users Index</a>
	<br />
</body>
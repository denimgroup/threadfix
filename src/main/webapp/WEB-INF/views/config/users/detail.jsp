<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ user.name }"/></title>
</head>

<body id="config">
	<h2 id="nameText"><c:out value="${ user.name }"/></h2>
	
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Role:</td>
				<td id="roleText" class="inputValue"><c:out value="${ user.role.displayName }"/></td>
			</tr>
		</tbody>
	</table>
	<br />
	<spring:url value="{userId}/edit" var="editUrl">
		<spring:param name="userId" value="${ user.id }"/>
	</spring:url>
	<a id="editLink" href="${ fn:escapeXml(editUrl) }">Edit</a> | 
	<spring:url value="{userId}/delete" var="deleteUrl">
		<spring:param name="userId" value="${ user.id }"/>
	</spring:url>
	<a id="deleteLink" href="${ fn:escapeXml(deleteUrl) }" onclick="return confirm('Are you sure you want to delete this Organization?')">Delete</a> | 
	<a id="backToListLink" href="<spring:url value="/configuration/users" />">Back to List</a>
	<br />
</body>
<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Manage Groups</title>
</head>

<body>
	<h2>Manage Groups</h2>
	
	<div id="helpText">
		ThreadFix Groups determine access to teams and applications.<br/>
	</div>
	
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="medium first">Name</th>
				<th class="medium">Team</th>
				<th>Parent Group</th>
				<th class="short">Edit</th>
				<th class="short">Delete</th>
				<th class="medium">Configure Users</th>
			</tr>
		</thead>
		<tbody>
			<c:if test="${ empty groupList}">
				<tr class="bodyRow">
					<td colspan="6" style="text-align:center;">No groups found.</td>
				</tr>
			</c:if>
			<c:forEach var="group" items="${ groupList }" varStatus="status">
				<tr class="bodyRow">
					<td id="group${ status.count }">
						<c:out value="${ group.name }"/>
					</td>
					<td id="team${ status.count }">
						<c:if test="${ empty group.team }">
							No team found
						</c:if>
						<c:if test="${ not empty group.team }">
							<c:out value="${ group.team.name }"/>
						</c:if>
					</td>
					<td id="parentGroup${ status.count }">
						<c:if test="${ empty group.parentGroup or not group.parentGroup.active}">
							No parent group found
						</c:if>
						<c:if test="${ not empty group.parentGroup and group.parentGroup.active}">
							<c:out value="${ group.parentGroup.name }"/>
						</c:if>
					</td>
					<td>
						<spring:url value="/configuration/groups/{groupId}/edit" var="groupEditUrl">
							<spring:param name="groupId" value="${ group.id }" />
						</spring:url>
						<a id="edit${ status.count }" href="${ fn:escapeXml(groupEditUrl) }">Edit</a> 
					</td>
					<td>
						<spring:url value="/configuration/groups/{groupId}/delete" var="groupDeleteUrl">
							<spring:param name="groupId" value="${ group.id }" />
						</spring:url>
						<form:form method="POST" action="${ fn:escapeXml(groupDeleteUrl) }">
							<input id="delete${ status.count }" type="submit" 
							onclick="return confirm('Are you sure you want to delete this Group? All users will have their privileges revoked.')" 
							value="Delete"/>
						</form:form>
					</td>
					<td>
						<spring:url value="/configuration/groups/{groupId}/users" var="userConfigUrl">
							<spring:param name="groupId" value="${ group.id }" />
						</spring:url>
						<a id="userConfig${ status.count }" href="${ fn:escapeXml(userConfigUrl) }">Configure Users</a> 
					</td>
				</tr>
			</c:forEach>
		</tbody>
	</table>
	<br/>
	<a id="createNewGroupLink" href="<spring:url value="/configuration/groups/new" />">Create New Group</a> |
	<a id="backToMenuLink" href="<spring:url value="/configuration" />">Back to Configuration Index</a>
	
</body>

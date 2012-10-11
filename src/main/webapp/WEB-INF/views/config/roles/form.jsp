<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Role <c:out value="${ role.name }"/></title>
</head>

<body>
	<h2><c:if test="${ role['new'] }">New </c:if>Role</h2>
	
	<spring:url value="" var="emptyUrl"></spring:url>	
	<form:form modelAttribute="role" method="post" action="${fn:escapeXml(emptyUrl) }">
		<table class="dataTable">
			<tbody>
				<tr>
					<td class="label">Name:</td>
					<td class="inputValue">
						<form:input path="displayName" size="70" maxlength="255" value="${ displayName }" />
					</td>
					<td style="padding-left:5px">
						<form:errors path="displayName" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td class="label">Code:</td>
					<td class="inputValue">
						<form:input path="name" cssClass="focus" size="70" maxlength="255" value="${ name }" />
					</td>
					<td style="padding-left:5px">
						<form:errors path="name" cssClass="errors" />
					</td>
				</tr>
			</tbody>
		</table>
		<br/>
		<c:if test="${ role['new'] }">
			<input id="createRoleButton" type="submit" value="Create Role" />
		</c:if>
		<c:if test="${ not role['new'] }">
			<input id="updateRoleButton" type="submit" value="Update Role" />
		</c:if>
		<span style="padding-left: 10px">
			<a id="backToRolesButton" href="<spring:url value="/configuration/roles"/>">Back to Roles</a>
		</span>
	</form:form>
</body>
<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Group Configuration</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
</head>

<h2>Group <c:out value="${ group.name }"/> Users Configuration</h2>

<spring:url value="" var="emptyUrl"/>
<form:form modelAttribute="groupUsersModel" method="post" action="${ fn:escapeXml(emptyUrl) }">
	<table class="formattedTable sortable filteredTable" id="anyid">
		<thead>
			<tr>
				<th class="first medium">Name</th>
				<th class="last unsortable">Select All <input type="checkbox" id="chkSelectAll" onclick="ToggleCheckboxes('anyid',1)"></th>
			</tr>
		</thead>
		<tbody>
		<c:if test="${ empty allUsers }">
			<tr class="bodyRow">
				<td colspan="2" style="text-align:center;">No users found.</td>
			</tr>
		</c:if>
		<c:forEach var="user" items="${ allUsers }" varStatus="status">
			<tr class="bodyRow">
				<td id="name${ status.count }"><c:out value="${ user.name }"/></td>
				<td>
					<input id="userIds${ status.count }" type="checkbox" value="${ user.id }" 
					<c:if test="${ activeIds.contains(user.id) }">
						checked="checked"
					</c:if>
					name="objectIds">
					<input type="hidden" value="on" name="_objectIds">
				</td>
			</tr>
		</c:forEach>
		</tbody>
	</table>
	<br/>

	<input id="submitButton" type="submit" value="Submit">
	<spring:url value="/configuration/groups" var="backUrl"/>
	<span style="padding-left:5px">
		<a id="backToGroupsPage" href="${fn:escapeXml(backUrl) }">Back To Groups Page</a>
	</span>
</form:form>
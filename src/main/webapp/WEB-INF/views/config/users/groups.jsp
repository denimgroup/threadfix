<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Group Configuration</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
</head>

<h2>User <c:out value="${ user.name }"/> Group Configuration</h2>

<spring:url value="" var="emptyUrl"/>
<form:form modelAttribute="userModel" method="post" action="${ fn:escapeXml(emptyUrl) }">
	<table class="formattedTable sortable filteredTable" id="anyid">
		<thead>
			<tr>
				<th class="first medium">Name</th>
				<th class="last unsortable">Select All <input type="checkbox" id="chkSelectAll" onclick="ToggleCheckboxes('anyid',1)"></th>
			</tr>
		</thead>
		<tbody>
		<c:if test="${ empty allGroups }">
			<tr class="bodyRow">
				<td colspan="2" style="text-align:center;">No groups found.</td>
			</tr>
		</c:if>
		<c:forEach var="group" items="${ allGroups }" varStatus="status">
			<tr class="bodyRow">
				<td id="name${ status.count }"><c:out value="${ group.name }"/></td>
				<td>
					<input id="groupIds${ status.count }" type="checkbox" value="${ group.id }" 
					<c:if test="${ activeIds.contains(group.id) }">
						checked="checked"
					</c:if>
					name="groupIds">
					<input type="hidden" value="on" name="_groupIds">
				</td>
			</tr>
		</c:forEach>
		</tbody>
	</table>
	<br/>

	<input id="submitButton" type="submit" value="Submit">
	<spring:url value="/configuration/users" var="backUrl"/>
	<span style="padding-left:5px"><a id="backToUserPageLink" href="${fn:escapeXml(backUrl) }">Back To User Page</a></span>
</form:form>
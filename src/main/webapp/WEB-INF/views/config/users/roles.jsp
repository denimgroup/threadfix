<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Role Configuration</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
</head>

<h2>User <c:out value="${ user.name }"/> Role Configuration</h2>

<c:if test="${ not empty error }">
	<span class="errors"><c:out value="${ error }"/></span>
</c:if>

<spring:url value="" var="emptyUrl"/>
<form:form modelAttribute="userModel" method="post" action="${ fn:escapeXml(emptyUrl) }">
	<table class="formattedTable sortable filteredTable" id="anyid" style="margin-top:10px">
		<thead>
			<tr>
				<th class="first medium">Name</th>
				<th class="last unsortable">Select All <input type="checkbox" id="chkSelectAll" onclick="ToggleCheckboxes('anyid',1)"></th>
			</tr>
		</thead>
		<tbody>
		<c:if test="${ empty allRoles }">
			<tr class="bodyRow">
				<td colspan="2" style="text-align:center;">No roles found.</td>
			</tr>
		</c:if>
		<c:forEach var="role" items="${ allRoles }" varStatus="status">
			<tr class="bodyRow">
				<td id="name${ status.count }"><c:out value="${ role.name }"/></td>
				<td>
					<input id="roleIds${ status.count }" type="checkbox" value="${ role.id }" 
					<c:if test="${ activeIds.contains(role.id) }">
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
	<spring:url value="/configuration/users" var="backUrl"/>
	<span style="padding-left:5px"><a id="backToUserPageLink" href="${fn:escapeXml(backUrl) }">Back To User Page</a></span>
</form:form>

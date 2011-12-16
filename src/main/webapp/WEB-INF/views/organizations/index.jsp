<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Organizations</title>
</head>

<body id="apps">
	<h2>Organizations</h2>
	
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="medium first">Organization</th>
				<th class="short">No. of Apps</th>
				<th class="short">Total Open</th>
				<th class="short">Critical</th>
				<th class="short">High</th>
				<th class="short">Medium</th>
				<th class="short">Low</th>
				<th class="short last">Info</th>
			</tr>
		</thead>
		<tbody id="orgTableBody">
		<c:if test="${ empty organizationList }">
			<tr class="bodyRow">
				<td colspan="8" style="text-align:center;">No organizations found.</td>
			</tr>
		</c:if>
		<c:forEach var="org" items="${ organizationList }">
			<tr class="bodyRow">
				<td class="details">
					<spring:url value="/organizations/{orgId}" var="orgUrl">
						<spring:param name="orgId" value="${ org.id }" />
					</spring:url>
					<a href="${ fn:escapeXml(orgUrl) }">
						<c:out value="${ org.name }"/>
					</a> 
				</td>
				<td>
					<c:out value="${ fn:length(org.activeApplications) }" />
				</td>
				<td><c:out value="${ org.vulnerabilityReport[5] }"/></td>
				<td><c:out value="${ org.vulnerabilityReport[4] }"/></td>
				<td><c:out value="${ org.vulnerabilityReport[3] }"/></td>
				<td><c:out value="${ org.vulnerabilityReport[2] }"/></td>
				<td><c:out value="${ org.vulnerabilityReport[1] }"/></td>
				<td><c:out value="${ org.vulnerabilityReport[0] }"/></td>
			</tr>
		</c:forEach>
			<tr class="footer">
				<td colspan="4" class="first">
					<a id="addOrganization" href="<spring:url value="/organizations/new" />">Add Organization</a>
				</td>
				<td colspan="3" class="last pagination" style="text-align:right"></td>
			</tr>
		</tbody>
	</table>
	<br/>
</body>

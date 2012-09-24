<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Home</title>
</head>

<body id="apps">
	<h2>Teams</h2>
	<div id="helpText">A Team is a group of developers who are responsible for the same application or applications.</div>
	
	<c:if test='${ shouldChangePassword }'>
		<div id="passwordNag" style="width:600px;font-weight:bold;">Our records indicate that you haven't changed your 
			password since your account was created. You should change it by going here:
			<spring:url value="/configuration/users/password" var="passwordChangeUrl"/>
			<a id="changePasswordLink" href="${ fn:escapeXml(passwordChangeUrl) }">Change My Password</a>
		</div>
	</c:if>
	
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="medium first">Team Name</th>
				<th class="short">No. of Apps</th>
				<th class="short">Open Vulns</th>
				<th class="short">Critical</th>
				<th class="short">High</th>
				<th class="short">Medium</th>
				<th class="short last">Low</th>
			</tr>
		</thead>
		<tbody id="orgTableBody">
		<c:if test="${ empty organizationList }">
			<tr class="bodyRow">
				<td colspan="8" style="text-align:center;">No teams found.</td>
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
			</tr>
		</c:forEach>
			<tr class="footer">
				<td colspan="4" class="first">
					<a id="addOrganization" href="<spring:url value="/organizations/new" />">Add Team</a>
				</td>
				<td colspan="3" class="last pagination" style="text-align:right"></td>
			</tr>
		</tbody>
	</table>
	<br/>
</body>

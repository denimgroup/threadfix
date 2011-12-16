<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ organization.name }"/></title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/sortable_us.js"></script>
</head>

<body id="apps">
	<h2 id="name"><c:out value="${ organization.name }"/></h2>
	
	<h3 class="top">Applications</h3>
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="medium first">Name</th>
				<th class="long">URL</th>
				<th class="short">Total Open</th>
				<th class="short">Critical</th>
				<th class="short">High</th>
				<th class="short">Medium</th>
				<th class="short">Low</th>
				<th class="short last">Info</th>
			</tr>
		</thead>
		<tbody id="applicationsTableBody">
	<c:choose>
		<c:when test="${empty organization.activeApplications}">
			<tr class="bodyRow">
				<td colspan="8" style="text-align:center;">No applications found.</td>
			</tr>
		</c:when>
		<c:otherwise>
			<c:forEach var="app" items="${ organization.activeApplications }">
			<tr class="bodyRow">
				<td>
					<spring:url value="{orgId}/applications/{appId}" var="appUrl">
						<spring:param name="orgId" value="${ organization.id }"/>
						<spring:param name="appId" value="${ app.id }"/>
					</spring:url>
					<a href="${ fn:escapeXml(appUrl) }"><c:out value="${ app.name }"/></a>
				</td>
				<td><c:out value="${ app.url }"/></td>
				<td><c:out value="${ app.vulnerabilityReport[5] }"/></td>
				<td><c:out value="${ app.vulnerabilityReport[4] }"/></td>
				<td><c:out value="${ app.vulnerabilityReport[3] }"/></td>
				<td><c:out value="${ app.vulnerabilityReport[2] }"/></td>
				<td><c:out value="${ app.vulnerabilityReport[1] }"/></td>
				<td><c:out value="${ app.vulnerabilityReport[0] }"/></td>
			</tr>
			</c:forEach>
		</c:otherwise>
	</c:choose>
			<tr class="footer">
				<td class="first" colspan="2">
					<spring:url value="{orgId}/applications/new" var="newAppUrl">
						<spring:param name="orgId" value="${ organization.id }"/>
					</spring:url>
					<a id="addApplicationLink" href="${ fn:escapeXml(newAppUrl) }">Add Application</a>
				</td>
				<td colspan="7" class="pagination last" style="text-align:right"></td>
			</tr>
		</tbody>
	</table>
	<c:if test="${not empty organization.applications}">
		<div style="padding-left:7px">
			<spring:url value="{orgId}/scans/sentinel" var="sentinelUrl">
				<spring:param name="orgId" value="${ organization.id }"/>
			</spring:url>
			<a id="importSentinelLink" href="${ fn:escapeXml(sentinelUrl) }">Import Sentinel</a>
		</div>
	</c:if>
	
	<h3>Surveys</h3>
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="long first">Survey</th>
				<th class="medium">User</th>
				<th class="medium">Status</th>
				<th class="last">Start On</th>
			</tr>
		</thead>
		<tbody>
	<c:choose>
		<c:when test="${ empty organization.surveyResults }">
			<tr class="bodyRow">
				<td colspan="4" style="text-align:center;"> No surveys found.</td>
			</tr>
		</c:when>
		<c:otherwise>
			<c:forEach var="result" items="${ organization.surveyResults }">
			<tr class="bodyRow">
				<td>
				<c:choose>
					<c:when test="${ !(result.status eq 'Submitted') }" >
						<spring:url value="{orgId}/surveys/{resultId}/edit" var="surveyUrl">
							<spring:param name="orgId" value="${ organization.id }" />
							<spring:param name="resultId" value="${ result.id }" />
						</spring:url>
					</c:when>
					<c:otherwise>
						<spring:url value="{orgId}/surveys/{resultId}" var="surveyUrl">
							<spring:param name="orgId" value="${ organization.id }" />
							<spring:param name="resultId" value="${ result.id }" />
						</spring:url>
					</c:otherwise>
				</c:choose>
					<a href="${ fn:escapeXml(surveyUrl)}">
						<c:out value="${ result.survey.name }"/>
					</a>
				</td>
				<td><c:out value="${ result.user }"/></td>
				<td><c:out value="${ result.status }"/></td>
				<td>
					<fmt:formatDate value="${ result.createdDate }" type="both" dateStyle="short" timeStyle="short" />
				</td>
			</tr>
			</c:forEach>
		</c:otherwise>
	</c:choose>
			<tr class="footer">
				<td colspan="2" class="first">
					<spring:url value="{orgId}/surveys/new" var="newSurveyUrl">
						<spring:param name="orgId" value="${ organization.id }" />
					</spring:url>
					<a href="${ fn:escapeXml(newSurveyUrl) }">Take a Survey</a>
				</td>
				<td colspan="2" class="pagination last" style="text-align:right"></td>
			</tr>
		</tbody>
	</table>
	<br />
	<spring:url value="{orgId}/edit" var="editUrl">
		<spring:param name="orgId" value="${ organization.id }"/>
	</spring:url>
	<a id="editOrganizationLink" href="${ fn:escapeXml(editUrl) }">Edit Organization</a> | 
	<spring:url value="{orgId}/delete" var="deleteUrl">
		<spring:param name="orgId" value="${ organization.id }"/>
	</spring:url>
	<a id="deleteLink" href="${ fn:escapeXml(deleteUrl) }" onclick="return confirm('Are you sure you want to delete this Organization?')">Delete Organization</a> | 
	<a id="backToList" href="<spring:url value="/organizations" />">Back to List</a>
</body>
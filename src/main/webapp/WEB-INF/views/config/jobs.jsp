<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Job Statuses</title>
</head>

<body id="config">
	<h2><c:choose><c:when test="${ viewAll }">All</c:when><c:otherwise>Open</c:otherwise></c:choose> Job Statuses</h2>
	
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="medium first">Type</th>
				<th>Status</th>
				<th class="medium last">Updated On</th>
				<th>Trackback URL</th>
			</tr>
		</thead>
		<tbody>
	<c:choose>
		<c:when test="${ empty jobStatusList }">
			<tr class="bodyRow">
				<td colspan="4" style="text-align:center">No jobs found.</td>
			</tr>
		</c:when>
		<c:otherwise>
			<c:forEach var="jobStatus" items="${ jobStatusList }">
			<tr class="bodyRow">
				<td>
					<c:out value="${ jobStatus.type }"/>
				</td>
				<td>
					<c:out value="${ jobStatus.status }"/>
				</td>
				<td>
					<fmt:formatDate value="${ jobStatus.startDate }" type="both" timeStyle="short" dateStyle="short" />
				</td>
				<td>
					<a href="<spring:url value="${ jobStatus.urlPath }"/>"><c:out value="${ jobStatus.urlText }"/></a>
				</td>
			</c:forEach>
		</c:otherwise>
	</c:choose>
			<tr class="footer">
				<td colspan="2">
			<c:choose>
				<c:when test="${ viewAll }">
					<a href="<spring:url value="/jobs/all" />">Update Statuses</a> | 
					<a href="<spring:url value="/jobs/open" />">View Open</a>
				</c:when>
				<c:otherwise>
					<a href="<spring:url value="/jobs/open" />">Update Statuses</a> |
					<a href="<spring:url value="/jobs/all" />">View All</a>
				</c:otherwise>
			</c:choose>	
				</td>
				<td class="pagination" style="text-align:right"></td>
			</tr>
		</tbody>
	</table>
</body>
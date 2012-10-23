<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><fmt:message key="mainMenu.title" /></title>
	<meta name="heading" content="<fmt:message key='mainMenu.heading'/>" />
</head>

<body id="apps">
	<h2>Finding Details</h2>
	
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Channel Vulnerability:</td>
				<td class="inputValue"><c:out value="${ finding.channelVulnerability.name }"/></td>
			</tr>
			<tr>
				<td class="label">Channel Severity:</td>
				<td class="inputValue"><c:out value="${ finding.channelSeverity.name }"/></td>
			</tr>
			<tr>
				<td class="label">Generic Vulnerability:</td>
				<td class="inputValue"><c:out value="${ finding.channelVulnerability.genericVulnerability.name }"/></td>
			</tr>
			<tr>
				<td class="label">Generic Severity:</td>
				<td class="inputValue"><c:out value="${ finding.channelSeverity.severityMap.genericSeverity.name }"/></td>
			</tr>
			<tr>
				<td class="label">Path:</td>
				<td class="inputValue"><c:out value="${ finding.surfaceLocation.path }"/></td>
			</tr>
			<tr>
				<td class="label">Parameter:</td>
				<td class="inputValue"><c:out value="${ finding.surfaceLocation.parameter }"/></td>
			</tr>
		</tbody>
	</table>
	
	<div style="padding-top:10px">
		<c:if test="${ not empty finding.vulnerability }">
			<spring:url value=".." var="scanUrl"/>
			<a href="${fn:escapeXml(scanUrl) }">View Scan</a>
			<br/>
			<spring:url value="../../../vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">
				<spring:param name="vulnerabilityId" value="${ finding.vulnerability.id }" />
			</spring:url>
			<a href="${ fn:escapeXml(vulnerabilityUrl) }">
				<c:out value="View Vulnerability"/>
			</a>
			<security:authorize ifAnyGranted="ROLE_CAN_MODIFY_VULNERABILITIES">
				<br/>
				<spring:url value="{findingId}/merge" var="mergeUrl">
					<spring:param name="findingId" value="${ finding.id }"/>
				</spring:url>
				<a href="${ fn:escapeXml(mergeUrl) }">Merge with Other Findings</a>
			</security:authorize>
		</c:if>
	</div>

	<h3>Data Flow</h3>
<c:choose>
	<c:when test="${ empty finding.dataFlowElements }">
		<p>This finding has no data flow elements</p>
	</c:when>
	<c:otherwise>
	<table class="dataTable">
		<tbody>
		<c:forEach var="flowElement" items="${ finding.dataFlowElements }">
			<tr>
				<td class="label">File Name:</td>
				<td class="inputValue"><c:out value="${ flowElement.sourceFileName }"/></td>
			</tr>
			<tr>
				<td class="label">Line Nbr:</td>
				<td class="inputValue"><c:out value="${ flowElement.lineNumber }"/></td>
			</tr>
			<tr>
				<td class="label">Line Text:</td>
				<td class="inputValue"><code><c:out value="${ flowElement.lineText }"/></code></td>
			</tr>
			<tr>
				<td class="label">Column Nbr:</td>
				<td class="inputValue"><c:out value="${ flowElement.columnNumber }"/></td>
			</tr>
			<tr>
				<td class="label">Sequence:</td>
				<td class="inputValue"><c:out value="${ flowElement.sequence }"/></td>
			</tr>
			<tr>
				<td colspan="2">============================================================</td>
			</tr>
		</c:forEach>
		</tbody>
	</table>
	</c:otherwise>
</c:choose>
</body>

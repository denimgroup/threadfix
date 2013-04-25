<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Finding Details</title>
	<meta name="heading" content="<fmt:message key='mainMenu.heading'/>" />
</head>

<body id="apps">

	<spring:url value="/organizations/{orgId}" var="orgUrl">
		<spring:param name="orgId" value="${ finding.scan.application.organization.id }" />
	</spring:url>
	<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
		<spring:param name="orgId" value="${ finding.scan.application.organization.id }" />
		<spring:param name="appId" value="${ finding.scan.application.id }" />
	</spring:url>
	<spring:url value="/organizations/{orgId}/applications/{appId}/scans/{scanId}" var="scanUrl">
		<spring:param name="orgId" value="${ finding.scan.application.organization.id }" />
		<spring:param name="appId" value="${ finding.scan.application.id }" />
		<spring:param name="scanId" value="${ finding.scan.id }" />
	</spring:url>

	<ul class="breadcrumb">
	    <li><a href="<spring:url value="/"/>">Teams</a> <span class="divider">/</span></li>
	    <li><a href="${ fn:escapeXml(orgUrl) }"><c:out value="${ finding.scan.application.organization.name }"/></a> <span class="divider">/</span></li>
	    <li><a href="${ fn:escapeXml(appUrl) }"><c:out value="${ finding.scan.application.name }"/></a><span class="divider">/</span></li>
	    <li><a href="${ fn:escapeXml(scanUrl) }"><fmt:formatDate value="${ finding.scan.importTime.time }" type="both" dateStyle="short" timeStyle="short"/> <c:out value="${ fn:escapeXml(finding.scan.applicationChannel.channelType.name) }"/> Scan</a><span class="divider">/</span></li>
	    <li class="active">Finding ${ fn:escapeXml(finding.id) }</li>
    </ul>

	<h2>Finding Details</h2>
	
	<div style="padding-bottom:10px">
		<c:if test="${ not empty finding.vulnerability }">
			<spring:url value="../../../vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">
				<spring:param name="vulnerabilityId" value="${ finding.vulnerability.id }" />
			</spring:url>
			<a class="btn" href="${ fn:escapeXml(vulnerabilityUrl) }">
				<c:out value="View Vulnerability"/>
			</a>
			<c:if test="${ canModifyVulnerabilities }">
				<spring:url value="{findingId}/merge" var="mergeUrl">
					<spring:param name="findingId" value="${ finding.id }"/>
				</spring:url>
				<a class="btn" href="${ fn:escapeXml(mergeUrl) }">Merge with Other Findings</a>
			</c:if>
		</c:if>
	</div>
	
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="bold">Scanner Vulnerability</td>
				<td class="inputValue"><c:out value="${ finding.channelVulnerability.name }"/></td>
			</tr>
			<tr>
				<td class="bold">Scanner Severity</td>
				<td class="inputValue"><c:out value="${ finding.channelSeverity.name }"/></td>
			</tr>
			<tr>
				<td class="bold">CWE Vulnerability</td>
				<td class="inputValue"><c:out value="${ finding.channelVulnerability.genericVulnerability.name }"/></td>
			</tr>
			<tr>
				<td class="bold">Severity</td>
				<td class="inputValue"><c:out value="${ finding.channelSeverity.severityMap.genericSeverity.name }"/></td>
			</tr>
			<tr>
				<td class="bold">Path</td>
				<td class="inputValue"><c:out value="${ finding.surfaceLocation.path }"/></td>
			</tr>
			<tr>
				<td class="bold">Parameter</td>
				<td class="inputValue"><c:out value="${ finding.surfaceLocation.parameter }"/></td>
			</tr>
		</tbody>
	</table>
	
	<c:if test="${ not empty finding.dataFlowElements }">
		<h3>Data Flow</h3>
		<table class="dataTable">
			<tbody>
			<c:forEach var="flowElement" items="${ finding.dataFlowElements }">
				<tr>
					<td class="bold">File Name</td>
					<td class="inputValue"><c:out value="${ flowElement.sourceFileName }"/></td>
				</tr>
				<tr>
					<td class="bold">Line Number</td>
					<td class="inputValue"><c:out value="${ flowElement.lineNumber }"/></td>
				</tr>
				<tr>
					<td class="bold">Line Text</td>
					<td class="inputValue"><code><c:out value="${ flowElement.lineText }"/></code></td>
				</tr>
				<tr>
					<td class="bold">Column Number</td>
					<td class="inputValue"><c:out value="${ flowElement.columnNumber }"/></td>
				</tr>
				<tr>
					<td class="bold">Sequence</td>
					<td class="inputValue"><c:out value="${ flowElement.sequence }"/></td>
				</tr>
				<tr>
					<td colspan="2">============================================================</td>
				</tr>
			</c:forEach>
			</tbody>
		</table>
	</c:if>
</body>

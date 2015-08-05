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
	    <li><a href="<spring:url value="/teams"/>">Applications Index</a><span class="divider">/</span></li>
	    <li><a href="${ fn:escapeXml(orgUrl) }">Team <c:out value="${ finding.scan.application.organization.name }"/></a> <span class="divider">/</span></li>
	    <li><a href="${ fn:escapeXml(appUrl) }">Application <c:out value="${ finding.scan.application.name }"/></a><span class="divider">/</span></li>
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
			<c:if test="${ not empty finding.urlReference }">
				<tr>
					<td class="bold">Link</td>
					<td class="inputValue"><a id="sourceUrl" href="<c:out value="${ finding.urlReference }"/>" target="_blank"><c:out value="${ finding.urlReference }"/></a></td>
				</tr>
			</c:if>
			<tr>
				<td class="bold">Scanner Vulnerability</td>
				<td class="inputValue" id="scannerVulnerabilityType"><c:out value="${ finding.channelVulnerability.name }"/></td>
			</tr>
			<tr>
				<td class="bold">Scanner Severity</td>
				<td class="inputValue" id="scannerSeverity"><c:out value="${ finding.channelSeverity.name }"/></td>
			</tr>
            <tr>
                <td class="bold">CWE Vulnerability</td>
                <td class="inputValue" id="genericVulnerabilityName">
                    <span tooltip="CWE-${ finding.channelVulnerability.genericVulnerability.displayId }">
                    <c:out value="${ finding.channelVulnerability.genericVulnerability.name }"/></span></td>
            </tr>
			<tr>
				<td class="bold">Severity</td>
				<td class="inputValue" id="genericSeverityName"><c:out value="${ finding.channelSeverity.severityMap.genericSeverity.displayName }"/></td>
			</tr>
            <tr>
                <td class="bold">Description</td>
                <td class="inputValue" id="longDescription" style="max-width:500px;word-wrap: break-word;"><c:out value="${ finding.longDescription }"/></td>
            </tr>
			<c:if test="${ empty finding.dependency }">			
				<tr>
					<td class="bold">Path</td>
					<td class="inputValue" id="path"><c:out value="${ finding.surfaceLocation.path }"/></td>
				</tr>
				<tr>
					<td class="bold">Parameter</td>
					<td class="inputValue" id="parameter"><c:out value="${ finding.surfaceLocation.parameter }"/></td>
				</tr>
				<tr>
					<td class="bold">Native ID</td>
					<td class="inputValue" id="nativeId">
						<c:if test="${ not empty finding.displayId }"><c:out value="${ finding.displayId }" /></c:if>
						<c:if test="${ empty finding.displayId }"><c:out value="${ finding.nativeId }" /></c:if>						
					</td>
				</tr>
				<tr>
					<td class="bold" >Attack String</td>
					<td class="inputValue"><PRE id="attackString"><c:out value="${ finding.attackString }"/></PRE></td>
				</tr>
				<tr class="odd">
					<td class="bold" valign=top>Scanner Detail</td>
					<td class="inputValue" style="word-wrap: break-word;list-style: square"><PRE id="scannerDetail"><c:out value="${ finding.scannerDetail }"/></PRE></td>
				</tr>
				<tr>
					<td class="bold" valign=top>Scanner Recommendation</td>
					<td class="inputValue" style="word-wrap: break-word;list-style: square"><PRE id="scannerRecommendation"><c:out value="${ finding.scannerRecommendation }"/></PRE></td>
				</tr>				
				<tr>
					<td class="bold" valign=top>Attack Request</td>
					<td class="inputValue" style="word-wrap: break-word;"><PRE id="attackRequest"><c:out value="${ finding.attackRequest }"/></PRE></td>
				</tr>
				<tr>
					<td class="bold" valign=top>Attack Response</td>
					<td class="inputValue" style="word-wrap: break-word;"><PRE id="attackResponse"><c:out value="${ finding.attackResponse }"/></PRE></td>
				</tr>
			</c:if>
			<c:if test="${ not empty finding.dependency }">			
				<tr>
					<td class="bold">Reference</td>
					<td class="inputValue" id="dependency">
						<c:out value="${ finding.dependency.refId } "/>
						(<a target="_blank" href="<c:out value="${ finding.dependency.refLink }"/>">View</a>)
					</td>	
				</tr>
                <tr>
                    <td class="bold" valign=top>File Name</td>
                    <td class="inputValue" style="word-wrap: break-word;"><PRE id="dependencyFileName"><c:out value="${ finding.dependency.componentName }"/></PRE></td>
                </tr>
                <tr>
                    <td class="bold" valign=top>File Path</td>
                    <td class="inputValue" style="word-wrap: break-word;"><PRE id="dependencyFilePath"><c:out value="${ finding.dependency.componentFilePath }"/></PRE></td>
                </tr>
                <tr>
                    <td class="bold" valign=top>Description</td>
                    <td class="inputValue" style="word-wrap: break-word;"><PRE id="dependencyDesc"><c:out value="${ finding.dependency.description }"/></PRE></td>
                </tr>
			</c:if>
            <tr>
                <td class="bold" valign=top>Raw Finding</td>
                <td class="inputValue" style="word-wrap: break-word;"><PRE id="rawFinding"><c:out value="${ finding.rawFinding }"/></PRE></td>
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

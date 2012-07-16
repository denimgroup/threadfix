<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Findings</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/sortable_us.js"></script>
</head>

<body id="apps">
	<h2><fmt:formatDate value="${ scan.importTime.time }" type="both" dateStyle="short" timeStyle="short"/> <c:out value="${ fn:escapeXml(scan.applicationChannel.channelType.name) }"/> Scan Findings</h2>

	<div id="helpText">
		This page lists various statistics about a set of scan results from one scan file.<br/>
	</div>

	<h3>Vulnerability Counts:</h3>
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Total Vulns</td>
				<td class="inputValue"><c:out value="${ vulnData[1] }"/></td>
			</tr>
			<tr>
				<td class="label">New Vulns</td>
				<td class="inputValue"><c:out value="${ vulnData[2] }"/></td>
			</tr>
			<tr>
				<td class="label">Old Vulns</td>
				<td class="inputValue"><c:out value="${ vulnData[3] }"/></td>
			</tr>
			<tr>
				<td class="label">Resurfaced Vulns</td>
				<td class="inputValue"><c:out value="${ vulnData[4] }"/></td>
			</tr>
			<tr>
				<td class="label">Closed Vulns</td>
				<td class="inputValue"><c:out value="${ vulnData[5] }"/></td>
			</tr>
		</tbody>
	</table>
	
	<h3>Information</h3>
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Total Scan Results</td>
				<td class="inputValue"><c:out value="${ scan.numberRepeatResults + scan.totalNumberSkippedResults + fn:length(scan.findings) }"/></td>
			</tr>
			<tr>
				<td class="label">Total Repeat Findings (not included below)</td>
				<td class="inputValue"><c:out value="${ scan.numberRepeatFindings }"/> findings (<c:out value="${ scan.numberRepeatResults }"/> total results)</td>
			</tr>
			<tr>
				<td class="label">Total Findings</td>
				<td class="inputValue"><c:out value="${ fn:length(scan.findings) }"/></td>
			</tr>
			<tr>
				<td class="label">Duplicate Results Skipped</td>
				<td class="inputValue"><c:out value="${ scan.totalNumberSkippedResults }"/></td>
			</tr>
			<tr>
				<td class="label">Total Findings matched to Vulnerabilities</td>
				<td class="inputValue"><c:out value="${ fn:length(scan.mappedFindings) }"/></td>
			</tr>
			<tr>
				<td class="label">Total Findings not matched to Vulnerabilities</td>
				<td class="inputValue"><c:out value="${ fn:length(scan.unmappedFindings) }"/></td>
			</tr>
			<tr>
				<td class="label">Findings merged to Vulnerabilities from other Findings in this Scan</td>
				<td class="inputValue"><c:out value="${ scan.totalNumberFindingsMergedInScan }"/></td>
			</tr>
			<tr>
				<td class="label">Number of Findings missing Channel Vulnerability mappings</td>
				<td class="inputValue"><c:out value="${ scan.numWithoutChannelVulns }"/></td>
			</tr>
			<tr>
				<td class="label">Number of Findings missing Generic Mappings</td>
				<td class="inputValue"><c:out value="${ scan.numWithoutGenericMappings }"/></td>
			</tr>
		</tbody>
	</table>
	<br />
	
	<h3>Successfully Mapped Findings:</h3>
	<table class="formattedTable sortable" id="1">
		<thead>
			<tr>
				<th class="first">Severity</th>
				<th>Vulnerability Type</th>
				<th>Path</th>
				<th>Parameter</th>
				<th>Vulnerability Link</th>
				<th class="last">Number Merged Results</th>
			</tr>
		</thead>
		<tbody>
	<c:choose>
		<c:when test="${ empty scan.mappedFindings }">
			<tr class="bodyRow">
				<td colspan="6" style="text-align: center;"> No Findings were mapped to vulnerabilities.</td>
			</tr>
		</c:when>
		<c:otherwise>
		<c:forEach var="finding" items="${ scan.mappedFindings }">
			<tr class="bodyRow">
				<td>
					<c:out value="${ finding.channelSeverity.name }"/>
				</td>
				<td>
					<spring:url value="{scanId}/findings/{findingId}" var="findingUrl">
					<spring:param name="scanId" value="${ scan.id }" />
						<spring:param name="findingId" value="${ finding.id }" />
					</spring:url>
					<a href="${ fn:escapeXml(findingUrl) }">
					    <c:out value="${ finding.channelVulnerability.name }"/>
					</a>
				</td>
				<td>
					<c:out value="${ finding.surfaceLocation.path }"/>
				</td>
				<td>
					<c:out value="${ finding.surfaceLocation.parameter }"/>
				</td>
				<td>
					<spring:url value="../vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">
				    	<spring:param name="vulnerabilityId" value="${ finding.vulnerability.id }" />
			    	</spring:url>
			    	<a href="${ fn:escapeXml(vulnerabilityUrl) }">
						<c:out value="${ finding.vulnerability.id }"/>
					</a>
				</td>
				<td>
					<c:out value="${ finding.numberMergedResults }"/>
				</td>
			</tr>
		</c:forEach>
		</c:otherwise>
	</c:choose>
		</tbody>
		<tfoot>
			<tr class="footer">
				<td colspan="4" class="pagination" style="text-align:right"></td>
			</tr>
		</tfoot>
	</table>
	
	<h3>Unmapped Findings:</h3>
	<table class="filteredTable sortable" id="2">
		<thead>
			<tr class="darkBackground">
				<th class="first">Severity</th>
				<th>Vulnerability Type</th>
				<th>Path</th>
				<th>Parameter</th>
				<th class="last">Number Merged Results</th>
			</tr>
		</thead>
		<tbody>
	<c:choose>
		<c:when test="${ empty scan.unmappedFindings }">
			<tr class="bodyRowNoPage">
				<td colspan="5" style="text-align: center;"> All Findings were successfully mapped.</td>
			</tr>
		</c:when>
		<c:otherwise>
		<c:forEach var="finding" items="${ scan.unmappedFindings }">
			<tr class="bodyRowNoPage">
				<td>
					<c:out value="${ finding.channelSeverity.name }"/>
				</td>
				<td>
					<spring:url value="{scanId}/findings/{findingId}" var="findingUrl">
					<spring:param name="scanId" value="${ scan.id }" />
						<spring:param name="findingId" value="${ finding.id }" />
					</spring:url>
					<a href="${ fn:escapeXml(findingUrl) }">
					    <c:out value="${ finding.channelVulnerability.name }"/>
					</a>
				</td>
				<td>
					<c:out value="${ finding.surfaceLocation.path }"/>
				</td>
				<td>
					<c:out value="${ finding.surfaceLocation.parameter }"/>
				</td>
				<td>
					<c:out value="${ finding.numberMergedResults }"/>
				</td>
			</tr>
		</c:forEach>
		</c:otherwise>
	</c:choose>
		</tbody>
	</table>
	
	<spring:url value="/organizations/{orgId}/applications/{appId}/scans" var="scanUrl">
		<spring:param name="orgId" value="${ scan.application.organization.id }" />
		<spring:param name="appId" value="${ scan.application.id }" />
	</spring:url>
	<a href="${ fn:escapeXml(scanUrl) }">Back to Scan Index</a>
</body>
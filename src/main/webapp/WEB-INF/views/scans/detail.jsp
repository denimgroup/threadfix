<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Findings</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/sortable_us.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
	<spring:url value="{scanId}/table" var="tableUrl">
		<spring:param name="scanId" value="${ scan.id }"/>
	</spring:url>
	<spring:url value="{scanId}/unmappedTable" var="unmappedTableUrl">
		<spring:param name="scanId" value="${ scan.id }"/>
	</spring:url>
	<script type="text/javascript">
	window.onload = function()
    {
		refillElement('#toReplace', '<c:out value="${ tableUrl }"/>', 1, '<c:out value="${ loginUrl }"/>');
		refillElement('#toReplace2', '<c:out value="${ unmappedTableUrl }"/>', 1, '<c:out value="${ loginUrl }"/>');
    };
    </script>
</head>

<body id="apps">
	<h2><fmt:formatDate value="${ scan.importTime.time }" type="both" dateStyle="short" timeStyle="short"/> 
	<c:out value="${ fn:escapeXml(scan.applicationChannel.channelType.name) }"/> Scan Findings</h2>

	<div id="helpText">
		This page lists various statistics about a set of scan results from one scan file.<br/>
	</div>
	
	<spring:url value="/organizations/{orgId}/applications/{appId}/scans" var="scanUrl">
		<spring:param name="orgId" value="${ scan.application.organization.id }" />
		<spring:param name="appId" value="${ scan.application.id }" />
	</spring:url>
	<div><a href="${ fn:escapeXml(scanUrl) }">Back to Scan Index</a></div>

	<h3>Vulnerability Counts:</h3>
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Total Vulnerabilities</td>
				<td class="inputValue"><c:out value="${ vulnData[1] }"/></td>
			</tr>
			<tr>
				<td class="label">New Vulnerabilities</td>
				<td class="inputValue"><c:out value="${ vulnData[2] }"/></td>
			</tr>
			<tr>
				<td class="label">Old Vulnerabilities</td>
				<td class="inputValue"><c:out value="${ vulnData[3] }"/></td>
			</tr>
			<tr>
				<td class="label">Resurfaced Vulnerabilities</td>
				<td class="inputValue"><c:out value="${ vulnData[4] }"/></td>
			</tr>
			<tr>
				<td class="label">Closed Vulnerabilities</td>
				<td class="inputValue"><c:out value="${ vulnData[5] }"/></td>
			</tr>
		</tbody>
	</table>
	
	<h3>Information</h3>
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Total Scan Results</td>
				<td class="inputValue">
					<c:out value="${ scan.numberRepeatResults + scan.totalNumberSkippedResults + 
										totalFindings + scan.numWithoutChannelVulns + scan.numWithoutGenericMappings }"/>
				</td>
			</tr>
			<tr>
				<td class="label">Total Repeat Findings (not included below)</td>
				<td class="inputValue"><c:out value="${ scan.numberRepeatFindings }"/> findings 
									(<c:out value="${ scan.numberRepeatResults }"/> total results)</td>
			</tr>
			<tr>
				<td class="label">Total Findings</td>
				<td class="inputValue"><c:out value="${ totalFindings + 
											scan.numWithoutChannelVulns + scan.numWithoutGenericMappings }"/></td>
			</tr>
			<tr>
				<td class="label">Duplicate Results Skipped</td>
				<td class="inputValue"><c:out value="${ scan.totalNumberSkippedResults }"/></td>
			</tr>
			<tr>
				<td class="label">Total Findings matched to Vulnerabilities</td>
				<td class="inputValue"><c:out value="${ totalFindings }"/></td>
			</tr>
			<tr>
				<td class="label">Total Findings not matched to Vulnerabilities</td>
				<td class="inputValue"><c:out value="${ scan.numWithoutChannelVulns + scan.numWithoutGenericMappings }"/></td>
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
	
	<c:if test="${ totalFindings + scan.numWithoutChannelVulns + scan.numWithoutGenericMappings == 0 }">
		<h3>Findings</h3>
		<table class="formattedTable" id="1">
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
				<tr class="bodyRow">
					<c:if test="${ scan.numberRepeatFindings != 0 }">
						<td colspan="6" style="text-align: center;">All Findings were linked to Findings from previous scans.</td>
					</c:if>
					<c:if test="${ scan.numberRepeatFindings == 0 }">
						<td colspan="6" style="text-align: center;">No Findings were found.</td>
					</c:if>
				</tr>
			</tbody>
		</table>
	</c:if>
	
	<c:if test="${ totalFindings + scan.numWithoutChannelVulns + scan.numWithoutGenericMappings != 0}">
		<div id="toReplace">
		<h3>Successfully Mapped Findings</h3>
		<table class="formattedTable" id="1">
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
				<tr class="bodyRow">
					<td colspan="6" style="text-align: center;">Loading Findings.</td>
				</tr>
			</tbody>
		</table>
		</div>
		
		<div id="toReplace2">
		<h3>Unmapped Findings</h3>
		<table class="formattedTable" id="2">
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
				<tr class="bodyRow">
					<td colspan="6" style="text-align: center;">Loading Findings.</td>
				</tr>
			</tbody>
		</table>
		</div>
	</c:if>
	
	<spring:url value="/organizations/{orgId}/applications/{appId}/scans" var="scanUrl">
		<spring:param name="orgId" value="${ scan.application.organization.id }" />
		<spring:param name="appId" value="${ scan.application.id }" />
	</spring:url>
	<a href="${ fn:escapeXml(scanUrl) }">Back to Scan Index</a>
</body>
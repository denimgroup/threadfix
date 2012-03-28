<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/></title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/confirm.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/sortable_us.js"></script>
</head>

<body id="apps">
	<spring:url value="/organizations/{orgId}" var="orgUrl">
		<spring:param name="orgId" value="${ application.organization.id }"/>
	</spring:url>
	<spring:url value="edit" var="editUrl">
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
	<spring:url value="delete" var="deleteUrl">
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
	
	<div style="font-size:150%">Team: <a id="organizationText" href="${fn:escapeXml(orgUrl)}"><c:out value="${ application.organization.name }"/></a></div>
	<br>
	<h2 style="padding-bottom:5px;" id="nameText">Application: <c:out value="${ application.name }"/>
	<span style="font-size:60%;padding-left:10px;">
		<a id="editLink" href="${ fn:escapeXml(editUrl) }">Edit</a> | 
		<a id="deleteLink" href="${ fn:escapeXml(deleteUrl) }" onclick="return confirm('Are you sure you want to delete the application?')">Delete</a>
	</span>
	</h2>
	
	<c:if test="${ not empty message }">
		<center class="errors" ><c:out value="${ message }"/> <a href="<spring:url value=""/>">Refresh the page.</a></center>
	</c:if>
	
	<div style="padding-top:10px;" id="helpText">
		You are viewing the closed vulns of the application.
	</div>
	<h3 style="padding-top:10px;">Information</h3>

	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">URL:</td>
				<td class="inputValue">
					<a id="urlText" href="<spring:url value="${ application.url }" />"><c:out value="${ application.url }" /></a>
				</td>
			</tr>
			<tr>
				<td class="label">Defect Tracker:</td>
		<c:choose>
			<c:when test="${ empty application.defectTracker }">
				<td class="inputValue">
					<spring:url value="/configuration/defecttrackers/new" var="newDTUrl"/>
					No Defect Tracker found.
				</td>
			</c:when>
			<c:otherwise>
				<td class="inputValue">
					<spring:url value="/configuration/defecttrackers/{defectTrackerId}" var="defectTrackerUrl">
						<spring:param name="defectTrackerId" value="${ application.defectTracker.id }"/>
					</spring:url>
					<a id="defectTrackerText" href="${ fn:escapeXml(defectTrackerUrl) }"><c:out value="${ application.defectTracker.name }"/></a>
					<em>(<a href="<spring:url value="${ fn:escapeXml(application.defectTracker.url) }" />"><c:out value="${ fn:escapeXml(application.defectTracker.url) }"/></a>)</em>
				</td>
			</c:otherwise>
		</c:choose>
			</tr>
			<tr>
				<td class="label">WAF:</td>
		<c:choose>
			<c:when test="${ empty application.waf }">
				<td class="inputValue">
					No WAF found.
				</td>
			</c:when>
			<c:otherwise>
				<td class="inputValue">
					<spring:url value="/wafs/{wafId}" var="wafUrl">
						<spring:param name="wafId" value="${ application.waf.id }"/>
					</spring:url>
					<a id="wafText" href="${ fn:escapeXml(wafUrl) }"><c:out value="${ application.waf.name }"/></a>
					<em>(<c:out value="${ application.waf.wafType.name }"/>)</em>
				</td>
			</c:otherwise>
		</c:choose>
			</tr>
		</tbody>
	</table>

	<div id="links" style="padding-bottom:10px;padding-top:10px">
		<spring:url value="scans/upload" var="uploadUrl">
			<spring:param name="appId" value="${ application.id }"/>
		</spring:url>
		<a id="uploadScanLink" href="${ fn:escapeXml(uploadUrl) }">Upload Scan</a> |
		<spring:url value="scans/sentinel" var="sentinelUrl">
			<spring:param name="appId" value="${ application.id }"/>
		</spring:url>
		<a id="importSentinelLink" href="${ fn:escapeXml(sentinelUrl) }">Import Sentinel</a> |
			<spring:url value="scans/new" var="addFindingUrl">
			<spring:param name="appId" value="${ application.id }"/>
		</spring:url>
		<a id="addFindingManuallyLink" href="${ fn:escapeXml(addFindingUrl) }">Add Finding Manually</a>
	</div>
	
	<c:if test="${ not empty application.scans }"> 
	<h3 style="padding-top:10px;">All Closed Vulnerabilities</h3>
	
	<p>Listing <c:out value="${ fn:length(application.closedVulnerabilities ) }"/>
		<c:choose>
			<c:when test="${ fn:length(application.closedVulnerabilities ) == 1 }">
				vulnerability
			</c:when>
			<c:otherwise>
				vulnerabilities
			</c:otherwise>
		</c:choose>
		from 
		<c:choose>
			<c:when test="${ fn:length(application.scans ) == 1 }">
				1 scan.
			</c:when>
			<c:otherwise>
				<c:out value="${ fn:length(application.scans) }"/> scans.
			</c:otherwise>
		</c:choose>
	</p>
	
	<c:if test="${ not empty application.activeVulnerabilities }">
		<spring:url value="/organizations/{orgId}/applications/{appId}" var="openVulnUrl">
			<spring:param name="appId" value="${ application.id }"/>
			<spring:param name="orgId" value="${ application.organization.id }"/>
		</spring:url>
	
		<a href="${ fn:escapeXml(openVulnUrl) }">View <c:out value="${ fn:length(application.activeVulnerabilities ) }"/> active Vulnerabilities.</a>
	</c:if>
	
	<br/><br/>
	
	<table class="formattedTable sortable" id="anyid">
		<thead>
			<tr>
				<th class="first">If Merged</th>
			    <th>Vulnerability Name</th>
				<th>Severity</th>
				<th>Path</th>
				<th>Parameter</th>
				<th>Defect</th>
				<th>Defect Status</th>
				<th>WAF Rule</th>
				<th class="last unsortable">WAF Events</th>
			</tr>
		</thead>
		<tbody>
		<c:if test="${ empty application.closedVulnerabilities }">
			<tr class="bodyRow">
				<td colspan="10" style="text-align:center;">No closed vulnerabilities found.</td>
			</tr>
		</c:if>
		<c:forEach var="vuln" items="${application.closedVulnerabilities}">
			<tr class="bodyRow">
				<td>
					<c:if test="${ fn:length(vuln.findings) > 1 }">
						<spring:url value="vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">
				        	<spring:param name="appId" value="${ application.id }" />
					    	<spring:param name="vulnerabilityId" value="${ vuln.id }" />
				    	</spring:url>
				    	<a href="${ fn:escapeXml(vulnerabilityUrl) }">
				        	<c:out value="${ fn:length(vuln.findings) }"/>
				    	</a>
					</c:if>
				</td>
				<td>
					<spring:url value="vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">
				        <spring:param name="appId" value="${ application.id }" />
					    <spring:param name="vulnerabilityId" value="${ vuln.id }" />
				    </spring:url>
				    <a href="${ fn:escapeXml(vulnerabilityUrl) }">
				        <c:out value="${ vuln.genericVulnerability.name }"/>
				    </a>
				</td>
				<td><c:out value="${ vuln.genericSeverity.name }"/></td>
				<td><c:out value="${ vuln.surfaceLocation.path }"/></td>
				<td><c:out value="${ vuln.surfaceLocation.parameter }"/></td>
				<td>
				<c:if test="${ not empty vuln.defect }">
					<spring:url value="vulnerabilities/{vulnerabilityId}/defect" var="defectUrl">
				        <spring:param name="appId" value="${ application.id }" />
					    <spring:param name="vulnerabilityId" value="${ vuln.id }" />
				    </spring:url>
					<a href="${ fn:escapeXml(defectUrl) }">
				        <c:out value="${ vuln.defect.nativeId }" />
				    </a>
				</c:if>
				</td>
				<td>
				<c:choose>
					<c:when test="${ not empty vuln.defect }">
						<c:out value="${ vuln.defect.status }"/>
					</c:when>
					<c:otherwise>
						No Defect
					</c:otherwise>
				</c:choose>
				</td>
				<td>
			<c:choose>
				<c:when test="${ not empty vuln.wafRules }">
					Yes
				</c:when>
				<c:otherwise>
					No
				</c:otherwise>
			</c:choose>
				</td>
				<td>
					<c:out value="${ vuln.noOfSecurityEvents }" />
				</td>
			</tr>
		</c:forEach>
		</tbody>
		<tfoot>
			<tr class="footer">
				<td colspan="9" class="pagination" style="text-align:right"></td>
			</tr>
		</tfoot>
	</table>

	<table class="dataTable">
		<tbody>
			<tr>
			<c:if test="${ not empty application.defectTracker }">
				<td class="label">Defect Tracker:</td>
				<td class="inputValue">
					<spring:url value="{appId}/defects" var="defectsUrl">
				        <spring:param name="appId" value="${ application.id }" />
				    </spring:url>
				    <a href="${ fn:escapeXml(defectsUrl) }">Submit Defects</a> |
				    <spring:url value="{appId}/defects/update" var="updateUrl">
				    	<spring:param name="appId" value="${ application.id }"/>
				    </spring:url>
					<a href="${ fn:escapeXml(updateUrl) }">Update Status from <c:out value="${application.defectTracker.defectTrackerType.name }"/></a>
				</td>
			</c:if>
			</tr>
			<tr>
				<td class="label">Jobs:</td>
				<td class="inputValue">
					<a href="<spring:url value="/jobs/open" />">View Open</a> |
					<a href="<spring:url value="/jobs/all" />">View All</a>
				</td>
			</tr>
		</tbody>
	</table>
	
	</c:if>
</body>
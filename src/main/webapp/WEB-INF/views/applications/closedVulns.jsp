<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/></title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/confirm.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/sortable_us.js"></script>
</head>

<body id="apps">
	<h2><c:out value="${ application.name }"/> - Closed Vulnerabilities</h2>
	
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Organization:</td>
				<td class="inputValue">
					<spring:url value="/organizations/{orgId}" var="orgUrl">
						<spring:param name="orgId" value="${ application.organization.id }"/>
					</spring:url>
					<a href="${fn:escapeXml(orgUrl)}"><c:out value="${ application.organization.name }"/></a>
				</td>
				<td class="label">Defect Tracker:</td>
		<c:choose>
			<c:when test="${ empty application.defectTracker }">
				<td class="inputValue">
					<spring:url value="{appId}/edit" var="editUrl">
						<spring:param name="appId" value="${ application.id }"/>
					</spring:url>
					<a href="${ editUrl }">None Selected</a>
				</td>
			</c:when>
			<c:otherwise>
				<td class="inputValue">
					<c:out value="${ application.defectTracker.defectTrackerType.name }"/> 
					<em>(<a href="<spring:url value="${ application.defectTracker.url }" />"><c:out value="${ application.defectTracker.url }"/></a>)</em>
				</td>
			</c:otherwise>
		</c:choose>
			</tr>
			<tr>
				<td class="label">URL:</td>
				<td class="inputValue">
					<a href="<spring:url value="${ application.url }" />">
						<c:out value="${ application.url }" />
					</a>
				</td>
				<td class="label">WAF:</td>
		<c:choose>
			<c:when test="${ empty application.waf }">
				<td class="inputValue">
					<a href="${ fn:escapeXml(editUrl) }">None Selected</a>
				</td>
			</c:when>
			<c:otherwise>
				<td class="inputValue">
					<c:out value="${ application.waf.wafType.name }"/> <em>(<c:out value="${ application.waf.name }"/>)</em>
				</td>
			</c:otherwise>
		</c:choose>
			</tr>
		</tbody>
	</table>
	<br />
	<spring:url value="edit" var="editUrl">
	</spring:url>
	<a href="${ fn:escapeXml(editUrl) }">Edit Application</a> | 
	<spring:url value="delete" var="deleteUrl">
	</spring:url>
	<a href="${ fn:escapeXml(deleteUrl) }" onclick="return confirm('Are you sure you want to delete the application?')">Delete Application</a> | 
	<spring:url value="scans" var="scanUrl">
	</spring:url>
	<a href="${ fn:escapeXml(scanUrl) }">View Scans</a> | 
	<spring:url value="scans/upload" var="uploadUrl">
	</spring:url>
	<a href="${ fn:escapeXml(uploadUrl) }">Upload Scan</a> |
	<spring:url value="scans/sentinel" var="sentinelUrl">
	</spring:url>
	<a href="${ fn:escapeXml(sentinelUrl) }">Import Sentinel</a> |
	<spring:url value="scans/new" var="addFindingUrl">
	</spring:url>
	<a href="${ fn:escapeXml(addFindingUrl) }">Add Finding Manually</a>
	<br/>
	<spring:url value="path" var="pathUrl">
	</spring:url>
	<a href="${ fn:escapeXml(pathUrl) }">View Path</a> |
	<spring:url value="path/surface_structure" var="surfaceStructureUrl">
	</spring:url>
	<a href="${ fn:escapeXml(surfaceStructureUrl) }">View Surface Structure</a> |
	<spring:url value="path/code_structure" var="codeStructureUrl">
	</spring:url>
	<a href="${ fn:escapeXml(codeStructureUrl) }">View Code Structure</a> |
	<spring:url value="falsepositives/mark" var="markFPUrl">
	</spring:url>
	<a href="${ fn:escapeXml(markFPUrl) }">Mark False Positives</a> |
	<spring:url value="falsepositives/unmark" var="unmarkFPUrl">
	</spring:url>
	<a href="${ fn:escapeXml(unmarkFPUrl) }">Unmark marked False Positives</a>
	

	<h3>Vulnerabilities</h3>
	
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
	
	<c:choose>
		<c:when test="${ not empty application.activeVulnerabilities }">
			<spring:url value="/organizations/{orgId}/applications/{appId}" var="openVulnUrl">
				<spring:param name="appId" value="${ application.id }"/>
				<spring:param name="orgId" value="${ application.organization.id }"/>
			</spring:url>
		
			<a href="${ fn:escapeXml(openVulnUrl) }">View <c:out value="${ fn:length(application.activeVulnerabilities ) }"/> active Vulnerabilities.</a>
		</c:when>
	</c:choose>
	
	<br/>
	
	<table class="formattedTable sortable" id="anyid">
		<thead>
			<tr>
				<th class="first">If Merged</th>
			    <th>Generic Vulnerability</th>
				<th>Generic Severity</th>
				<th>Path</th>
				<th>Parameter</th>
				<th>Defect</th>
				<th>Status</th>
				<th>WAF Rule</th>
				<th class="last unsortable">WAF Events</th>
			</tr>
		</thead>
		<tbody>
		<c:if test="${ empty application.closedVulnerabilities }">
			<tr class="bodyRow">
				<td colspan="9" style="text-align:center;">No closed vulnerabilities found.</td>
			</tr>
		</c:if>
		<c:forEach var="vuln" items="${application.closedVulnerabilities}">
			<tr class="bodyRow">
				<td>
					<c:if test="${ fn:length(vuln.findings) > 1 }">
						<spring:url value="vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">
					    	<spring:param name="vulnerabilityId" value="${ vuln.id }" />
				    	</spring:url>
				    	<a href="${ fn:escapeXml(vulnerabilityUrl) }">
				        	Yes
				    	</a>
					</c:if>
				</td>
				<td>
					<spring:url value="vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">
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
					    <spring:param name="vulnerabilityId" value="${ vuln.id }" />
				    </spring:url>
					<a href="${ fn:escapeXml(defectUrl) }">
				        <c:out value="${ vuln.defect.nativeId }" />
				    </a>
				</c:if>
				</td>
				<td>
					<c:out value="${ vuln.isOpen }"/>
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
</body>
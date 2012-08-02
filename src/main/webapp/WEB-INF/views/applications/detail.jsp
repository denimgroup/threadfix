<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/></title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/confirm.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
	<script type="text/javascript">
	window.onload = function()
    {
		toggleFilters(false, null, null);//refillElement('#toReplace', '${ application.id }/table', 1);
    };
    </script>
	
</head>

<body id="apps">
	<spring:url value="/organizations/{orgId}" var="orgUrl">
		<spring:param name="orgId" value="${ application.organization.id }"/>
	</spring:url>
	<spring:url value="{appId}/edit" var="editUrl">
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
	<spring:url value="{appId}/delete" var="deleteUrl">
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
	
	<div style="font-size:150%">Team: <a id="organizationText" href="${fn:escapeXml(orgUrl)}"><c:out value="${ application.organization.name }"/></a></div>
	<br>
	<h2 style="padding-bottom:5px;">Application: <span id="nameText"><c:out value="${ application.name }"/></span>
	<span style="font-size:60%;padding-left:10px;">
		<a id="editLink" href="${ fn:escapeXml(editUrl) }">Edit</a> | 
		<a id="deleteLink" href="${ fn:escapeXml(deleteUrl) }" onclick="return confirm('Are you sure you want to delete the application?')">Delete</a>
	</span>
	</h2>
	
	<c:if test="${ not empty message }">
		<center class="errors" ><c:out value="${ message }"/> <a id="refreshLink" href="<spring:url value=""/>">Refresh the page.</a></center>
	</c:if>
	
	<c:if test="${ not empty error }">
		<center class="errors" ><c:out value="${ error }"/></center>
	</c:if>
	
	<div style="padding-top:10px;" id="helpText">
		Applications are used to store, unify, and manipulate scan results from security scanners.
		<c:if test="${ empty application.scans }">
			<br/><br/>To get started, click Upload Scan to start uploading security scans.
		</c:if>
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
			<tr>
				<td class="label">Criticality:</td>
				<td class="inputValue"><c:out value="${ application.applicationCriticality.name }"/></td>
			</tr>
		</tbody>
	</table>

	<div id="links" style="padding-bottom:10px;padding-top:10px">
		<spring:url value="{appId}/scans/upload" var="uploadUrl">
			<spring:param name="appId" value="${ application.id }"/>
		</spring:url>
		<a id="uploadScanLink" href="${ fn:escapeXml(uploadUrl) }">Upload Scan</a> |
		<spring:url value="{appId}/scans/new" var="addFindingUrl">
			<spring:param name="appId" value="${ application.id }"/>
		</spring:url>
		<a id="addFindingManuallyLink" href="${ fn:escapeXml(addFindingUrl) }">Manually Add Vulnerabilities</a>
	</div>
	
	<c:if test="${ not empty application.scans }"> 
	<h3 style="padding-top:10px;">All Open Vulnerabilities</h3>
	
	<p>Listing <c:out value="${ numVulns }"/>
		<c:choose>
			<c:when test="${ numVulns == 1 }">
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
		<spring:url value="{appId}/scans" var="scanUrl">
			<spring:param name="appId" value="${ application.id }"/>
		</spring:url>
		
		<a id="viewScansLink" href="${ fn:escapeXml(scanUrl) }">View Scans</a>
		<c:if test="${ falsePositiveCount > 0 }">
			<spring:url value="{appId}/falsepositives/unmark" var="unmarkFPUrl">
				<spring:param name="appId" value="${ application.id }"/>
			</spring:url>
			<span style="padding-left:2px;"><a id="unmarkMarkedFalsePositivesLink" href="${ fn:escapeXml(unmarkFPUrl) }">
				<c:if test="${ falsePositiveCount == 1 }">
					View / Unmark 1 False Positive</c:if>
				<c:if test="${ falsePositiveCount > 1 }">
					View / Unmark <c:out value="${ falsePositiveCount }"/> False Positives</c:if>
			</a></span>
		</c:if>
	</p>

	<c:choose>
		<c:when test="${ not empty application.closedVulnerabilities }">
			<spring:url value="{appId}/closedVulnerabilities" var="closedVulnUrl">	
				<spring:param name="appId" value="${ application.id }"/>
			</spring:url>	
			<a href="${ fn:escapeXml(closedVulnUrl) }">View <c:out value="${ fn:length(application.closedVulnerabilities ) }"/> closed 
			<c:choose>
			<c:when test="${ fn:length(application.closedVulnerabilities ) == 1 }">
				Vulnerability.
			</c:when>
			<c:otherwise>
				Vulnerabilities.
			</c:otherwise>
		</c:choose></a>
		</c:when>
	</c:choose>

	<spring:url value="{appId}/falsepositives/mark" var="markFPUrl">
       	<spring:param name="appId" value="${ application.id }" />
   	</spring:url>
	<form:form modelAttribute="falsePositiveModel" method="post" action="${ fn:escapeXml(markFPUrl) }">
	
	<spring:url value="{appId}/table" var="tableUrl">
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
	
	<table class="dataTable">
			<tbody>
				<tr>
					<td rowspan="4" style="padding-bottom:10px; vertical-align:top">
						<div class="buttonGroup" id="vulnerabilityFilters">
							<table style="margin:0px;padding:0px;margin-left:auto;">
								<tr>
									<td colspan="2"><b>Vulnerability Name:</b></td>
									<td style="padding-left:5px; padding-top:3px"><input type="text" id="descriptionFilterInput" /></td>
								</tr>
								<tr>
									<td colspan="2"><b>Severity:</b></td>
									<td style="padding-left:5px; padding-top:3px"><input type="text" id="severityFilterInput" /></td>
								</tr>
								<tr>
									<td colspan="2"><b>Location:</b></td>
									<td style="padding-left:5px; padding-top:3px"><input type="text" id="locationFilterInput"/></td>
								</tr>
								<tr>
									<td colspan="2"><b>Parameter:</b></td>
									<td style="padding-left:5px; padding-top:3px"><input type="text" id="parameterFilterInput" /></td>
								</tr>
								<tr>
									<td><a href="javascript:filter('#toReplace', '${ tableUrl }');">Filter</a>&nbsp;|&nbsp;</td>
									<td><a href="javascript:clearFilters('#toReplace', '${ tableUrl }');">Clear Filters</a>&nbsp;|&nbsp;</td>
									<td><a href="javascript:toggleFilters(false, '#toReplace', '${ tableUrl }');">Hide Filters</a></td>
								</tr>
							</table>
						</div>
						<div id="showFilters" style="display:none;">
							<a href="javascript:toggleFilters(true, '#toReplace', '${ tableUrl }');">Show Filters</a>
						</div>
						<script>toggleFilters(false, '#toReplace', '${ tableUrl }');</script>
					</td>
				</tr>
			</tbody>
		</table>
    
    <div id="toReplace">
   
		<table class="formattedTable sortable filteredTable" id="anyid">
			<thead>
				<tr>
					<th class="first">If Merged</th>
				    <th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 1)">Vulnerability Name</th>
					<th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 2)">Severity</th>
					<th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 3)">Path</th>
					<th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 4)">Parameter</th>
					<th>Defect</th>
					<th>Defect Status</th>
					<th>WAF Rule</th>
					<th class="unsortable">WAF Events</th>
					<th class="last unsortable">Select All <input type="checkbox" id="chkSelectAll" onclick="ToggleCheckboxes('anyid',9)"></th>
				</tr>
			</thead>
			<tbody>
				<tr class="bodyRow">
					<td colspan="10" style="text-align:center;">Loading Vulnerabilities.</td>
				</tr>
			</tbody>
			<tfoot>
				<tr class="footer">
					<td colspan="10" style="text-align:right">
						<input type="submit" value="Mark Selected as False Positives">
					</td>
				</tr>
			</tfoot>
		</table>
	
	</div>
	
	</form:form>

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
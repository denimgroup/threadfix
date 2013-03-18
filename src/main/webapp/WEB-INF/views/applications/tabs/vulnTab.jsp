<%@ include file="/common/taglibs.jsp"%>

<c:if test="${ not empty application.scans }"> 
<p>Listing <span id="totalVulnCount"><c:out value="${ numVulns }"/></span>
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
</p>

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
							<td style="padding-left:5px; padding-top:3px"><input class="disableSubmitOnEnter" type="text" id="descriptionFilterInput" /></td>
						</tr>
						<tr>
							<td colspan="2"><b>CWE ID:</b></td>
							<td style="padding-left:5px; padding-top:3px"><input class="disableSubmitOnEnter" type="text" id="cweFilterInput" /></td>
						</tr>
						<tr>
							<td colspan="2"><b>Severity:</b></td>
							<td style="padding-left:5px; padding-top:3px"><input class="disableSubmitOnEnter" type="text" id="severityFilterInput" /></td>
						</tr>
						<tr>
							<td colspan="2"><b>Location:</b></td>
							<td style="padding-left:5px; padding-top:3px"><input class="disableSubmitOnEnter" type="text" id="locationFilterInput"/></td>
						</tr>
						<tr>
							<td colspan="2"><b>Parameter:</b></td>
							<td style="padding-left:5px; padding-top:3px"><input class="disableSubmitOnEnter" type="text" id="parameterFilterInput" /></td>
						</tr>
						<tr>
							<td><a id="filterLink" href="javascript:filter('#toReplace', '${ tableUrl }');">Filter</a>&nbsp;|&nbsp;</td>
							<td><a id="clearFilterLink" href="javascript:clearFilters('#toReplace', '${ tableUrl }');">Clear Filters</a>&nbsp;|&nbsp;</td>
							<td><a id="hideFilterLink" href="javascript:toggleFilters(false, '#toReplace', '${ tableUrl }');">Hide Filters</a></td>
						</tr>
					</table>
				</div>
				<div id="showFilters" style="display:none;">
					<a id="showFiltersLink" href="javascript:toggleFilters(true, '#toReplace', '${ tableUrl }');">Show Filters</a>
				</div>
				<script>toggleFilters(false, '#toReplace', '${ tableUrl }');</script>
			</td>
		</tr>
	</tbody>
</table>

   <div id="toReplace">
  
	<table class="table auto sortable" id="anyid">
		<thead>
			<tr>
				<th class="first">If Merged</th>
			    <th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 1, '<c:out value="${ loginUrl }"/>')">Vulnerability Name</th>
				<th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 2, '<c:out value="${ loginUrl }"/>')">Severity</th>
				<th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 3, '<c:out value="${ loginUrl }"/>')">Path</th>
				<th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 4, '<c:out value="${ loginUrl }"/>')">Parameter</th>
				<th>Age</th>
				<th>Defect</th>
				<th>Defect Status</th>
				<th>WAF Rule</th>
				<c:if test="${ not canModifyVulnerabilities }">
					<th class="unsortable last">WAF Events</th>
				</c:if>
				<c:if test="${ canModifyVulnerabilities }">
					<th class="unsortable">WAF Events</th>
					<th class="last unsortable">Select All <input type="checkbox" id="chkSelectAll" onclick="ToggleCheckboxes('anyid',10)"></th>
				</c:if>
			</tr>
		</thead>
		<tbody>
			<tr class="bodyRow">
				<c:if test="${ canModifyVulnerabilities }">
					<td colspan="12" style="text-align:center;">Loading Vulnerabilities.</td>
				</c:if>
				
				<c:if test="${ not canModifyVulnerabilities }">
					<td colspan="11" style="text-align:center;">Loading Vulnerabilities.</td>
				</c:if>
			</tr>
		</tbody>
		<c:if test="${ canModifyVulnerabilities }">
			<tfoot>
				<tr class="footer">
					<td colspan="12" style="text-align:right">
						<input type="submit" value="Mark Selected as False Positives">
					</td>
				</tr>
			</tfoot>
		</c:if>
	</table>

</div>

</form:form>

<table class="dataTable">
	<tbody>
		<tr>
		<c:if test="${ not empty application.defectTracker }">
			<td>Defect Tracker:</td>
			<td class="inputValue">
				<c:if test="${ canSubmitDefects }">
					<spring:url value="{appId}/defects" var="defectsUrl">
				        <spring:param name="appId" value="${ application.id }" />
				    </spring:url>
				    <a href="${ fn:escapeXml(defectsUrl) }">Submit Defects</a> |
			    </c:if>
			    <spring:url value="{appId}/defects/update" var="updateUrl">
			    	<spring:param name="appId" value="${ application.id }"/>
			    </spring:url>
				<a href="${ fn:escapeXml(updateUrl) }">Update Status from <c:out value="${application.defectTracker.defectTrackerType.name }"/></a>
			</td>
		</c:if>
		</tr>
		<c:if test="${ canViewJobStatuses }">
		<tr>
			<td>Jobs:</td>
			<td class="inputValue">
				<a href="<spring:url value="/jobs/open" />">View Open</a> |
				<a href="<spring:url value="/jobs/all" />">View All</a>
			</td>
		</tr>
		</c:if>
	</tbody>
</table>

</c:if>

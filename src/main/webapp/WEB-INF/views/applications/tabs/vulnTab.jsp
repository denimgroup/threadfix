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
  
	<table class="table sortable" id="anyid">
		<thead>
			<tr>
				<c:if test="${ canModifyVulnerabilities }">
					<th class="first unsortable"><input type="checkbox" id="chkSelectAll" onclick="ToggleCheckboxes('anyid',0)"></th>
					<th onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 1, '<c:out value="${ loginUrl }"/>')">Vulnerability Name</th>
				</c:if>			    
				<c:if test="${ not canModifyVulnerabilities }">
					<th class="first" onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 1, '<c:out value="${ loginUrl }"/>')">Vulnerability Name</th>
				</c:if>			    
				<th onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 2, '<c:out value="${ loginUrl }"/>')">Severity</th>
				<th onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 3, '<c:out value="${ loginUrl }"/>')">Path</th>
				<th onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 4, '<c:out value="${ loginUrl }"/>')">Parameter</th>
				
			</tr>
		</thead>
		<tbody>
			<tr class="bodyRow">
				<c:if test="${ canModifyVulnerabilities }">
					<td colspan="5" style="text-align:center;">Loading Vulnerabilities.</td>
				</c:if>
				
				<c:if test="${ not canModifyVulnerabilities }">
					<td colspan="4" style="text-align:center;">Loading Vulnerabilities.</td>
				</c:if>
			</tr>
		</tbody>
	</table>

</div>

</form:form>

</c:if>

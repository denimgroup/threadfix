<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Defect Submission</title>
<cbs:cachebustscript src="/scripts/remote-pagination.js"/>
	<spring:url value="defectTable" var="tableUrl" />
	<script type="text/javascript">
        window.onload = function() {
            //toggleFilters(false, '#toReplace', '${ tableUrl }');
            clearFilters('#toReplace', '${ tableUrl }');
        };
    </script>
</head>

<body id="apps">
	<h2>
	<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
		<spring:param name="orgId" value="${ application.organization.id }"/>
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
	<a ng-non-bindable href="${ fn:escapeXml(appUrl) }"><c:out value="${ application.name }"/></a> - New Defect</h2>
	
	<c:if test="${ not empty message }">
		<center ng-non-bindable class="errors" ><c:out value="${ message }"/></center>
	</c:if>
	
	<table class="dataTable">
		<tbody ng-non-bindable>
			<tr>
				<td>Team:</td>
				<td class="inputValue"><c:out value="${ application.organization.name }"/></td>
				<td>Defect Tracker:</td>
				<c:choose>
					<c:when test="${ empty application.defectTracker }">
						<td class="inputValue">
							<a href="${ fn:escapeXml(editUrl) }">None Selected</a>
						</td>
					</c:when>
					<c:otherwise>
						<td class="inputValue">
							<c:out value="${application.defectTracker.defectTrackerType.name }"/> 
							<em>(<a href="<spring:url value="${ application.defectTracker.url }" />"><c:out value="${ application.defectTracker.url }"/></a>)</em>
						</td>
						<td>Product:</td>
						<td class="inputValue">
							<c:out value="${ application.projectName}"/>
						</td>
					</c:otherwise>
				</c:choose>
			</tr>
			<tr>
				<td>URL:</td>
				<td class="inputValue">
					<a href="<spring:url value="${ application.url }" />">
						<c:out value="${ application.url }" />
					</a>
				</td>
				<td>WAF:</td>
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
	
	<div class="section">
	<h3>Defect Details</h3>
	<spring:url value="" var="emptyUrl"/>
	<form:form modelAttribute="defectViewModel" method="post" action="${ fn:escapeXml(emptyUrl) }">
		<table class="dataTable">
			<tbody>
				<tr>
					<td>Component:</td>
					<td class="inputValue">
						<form:select style="width:120px;" path="selectedComponent">
							<form:options items="${projectMetadata.components}"/>
						</form:select>
					</td>
					
					<td>Version:</td>
					<td class="inputValue">
						<form:select style="width:120px;" path="version">
							<form:options items="${projectMetadata.versions}"/>
						</form:select>
					</td>
					<td>Severity:</td>
					<td class="inputValue">
						<form:select style="width:120px;" path="severity">
							<form:options items="${projectMetadata.severities}"/>
						</form:select>
					</td>
				</tr>
				<tr>
					<td>Priority:</td>
					<td class="inputValue">
						<form:select style="width:120px;" path="priority">
							<form:options items="${projectMetadata.priorities}"/>
						</form:select>
					</td>
					<td>Status:</td>
					<td class="inputValue">
						<form:select style="width:120px;" path="status">
							<form:options items="${projectMetadata.statuses}"/>
						</form:select>
					</td>
				</tr>
				<tr>
					<td>Title:</td>
					<td colspan="5" class="inputValue">
						<form:input style="width:549px;" path="summary"/>
					</td>
				</tr>
				<tr style="margin-top:5px;">
					<td style="vertical-align:top">Description:</td>
					<td colspan="5" class="inputValue">
						<form:textarea path="preamble" style="width:549px; height:100px;"/>
					</td>
				</tr>
			</tbody>
		</table>
		
		<div class="buttonGroup" id="vulnerabilityFilters">
			<h3>Filters</h3>
			<table style="margin-bottom:20px;">
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
					<td style="padding-bottom: 1em;" colspan="2"><b>Parameter:</b></td>
					<td style="padding-left:5px; padding-top:3px;padding-bottom: 1em;"><input class="disableSubmitOnEnter" type="text" id="parameterFilterInput" /></td>
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
		
		<input style="margin-top:5px; margin-bottom:5px;" type="submit" value="Add Defect">
		
		<div id="toReplace">
			<table id="vulnerabilities" class="table table-striped sortable">
				<thead>
					<tr>
						<th class="first">Defect Id</th>
						<th>Status</th>
						<th>Generic Vulnerability (Description)</th>
						<th>Generic Severity</th>
						<th>Location</th>
						<th>Parameter</th>
						<th class="last unsortable">Select (All <input type="checkbox" id="chkSelectAll" onclick="ToggleCheckboxes('vulnerabilities',6)">)</th>
					</tr>
				</thead>
				<tbody>
					<tr class="bodyRow">
						<td colspan="7" style="text-align:center;">
							Loading Vulnerabilities.
						</td>
					</tr>
				</tbody>
			</table>
		</div>
			
		<input style="margin-top:5px;" type="submit" value="Add Defect">
	</form:form>
	</div>
</body>
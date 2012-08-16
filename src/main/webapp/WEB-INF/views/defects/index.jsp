<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Defect Submission</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
	<spring:url value="defectTable" var="tableUrl" />
	<script type="text/javascript">
	window.onload = function()
    {
		toggleFilters(false, '#toReplace', '${ tableUrl }');
		//toggleFilters(true, '#toReplace', '${ tableUrl }');
    };
    </script>
</head>

<body id="apps">
	<h2>
	<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
		<spring:param name="orgId" value="${ application.organization.id }"/>
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
	<a href="${ fn:escapeXml(appUrl) }"><c:out value="${ application.name }"/></a> - New Defect</h2>
	
	<c:if test="${ not empty message }">
		<center class="errors" ><c:out value="${ message }"/></center>
	</c:if>
	
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Team:</td>
				<td class="inputValue"><c:out value="${ application.organization.name }"/></td>
				<td class="label">Defect Tracker:</td>
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
						<td class="label">Product:</td>
						<td class="inputValue">
							<c:out value="${ application.projectName}"/>
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
	
	<div class="section">
	<spring:url value="" var="emptyUrl"/>
	<form:form modelAttribute="defectViewModel" method="post" action="${ fn:escapeXml(emptyUrl) }">
		<table class="dataTable">
			<tbody>
				<tr>
					<td class="label">Component:</td>
					<td class="inputValue">
						<form:select path="selectedComponent">
							<form:options items="${projectMetadata.components}"/>
						</form:select>
					</td>
					<td rowspan="4" style="padding-left:20px; vertical-align:top">
						<table>
								<tr>
									<td class="label">Summary:</td>
								</tr>
								<tr>
									<td class="inputValue">
										<form:input path="summary"/>
									</td>
								</tr>
								<tr>
									<td class="label">Preamble:</td>
								</tr>
								<tr>
									<td class="inputValue">
										<form:textarea path="preamble" />
									</td>
								</tr>
							</tbody>
						</table>	
					</td>
				</tr>
				<tr>
					<td class="label">Version:</td>
					<td class="inputValue">
						<form:select path="version">
							<form:options items="${projectMetadata.versions}"/>
						</form:select>
					</td>
				</tr>
				<tr>
					<td class="label">Severity:</td>
					<td class="inputValue">
						<form:select path="severity">
							<form:options items="${projectMetadata.severities}"/>
						</form:select>
					</td>
				</tr>
				<tr>
					<td class="label">Priority:</td>
					<td class="inputValue">
						<form:select path="priority">
							<form:options items="${projectMetadata.priorities}"/>
						</form:select>
					</td>
				</tr>
				<tr>
					<td class="label">Status:</td>
					<td class="inputValue">
						<form:select path="status">
							<form:options items="${projectMetadata.statuses}"/>
						</form:select>
					</td>
				</tr>
			</tbody>
		</table>
		
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
									<td><a href="javascript:filter('#toReplace', '${ tableUrl }');">Filter</a>&nbsp;|&nbsp;</td>
									<td><a href="javascript:clearFilters('#toReplace', '${ tableUrl }');">Clear Filters</a>&nbsp;|&nbsp;</td>
									<td><a href="javascript:toggleFilters(false, '#toReplace', '${ tableUrl }');">Hide Filters</a></td>
								</tr>
							</table>
						</div>
						<div id="showFilters" style="display:none;">
							<a href="javascript:toggleFilters(true, '#toReplace', '${ tableUrl }');">Show Filters</a>
						</div>
					</td>
				</tr>
			</tbody>
		</table>
		
		<div id="toReplace">
			<table id="vulnerabilities" class="formattedTable sortable">
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
			
		<input type="submit" value="Add Defect">
	</form:form>
	</div>
</body>
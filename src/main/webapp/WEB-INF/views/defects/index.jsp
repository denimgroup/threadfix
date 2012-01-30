<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Defects</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/tablefilter.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/sortable_us.js"></script>
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
					<td class="label">Compocnent:</td>
					<td class="inputValue">
						<form:select path="selectedComponent">
							<form:options items="${projectMetadata.components}"/>
						</form:select>
					</td>
					<td rowspan="4" style="padding-left:20px; vertical-align:top">
						<div class="buttonGroup" id="vulnerabilityFilters">
							<table style="margin:0px;padding:0px;margin-left:auto;">
								<tr>
									<td colspan="2"><b>Filter by description:</b></td>
									<td style="padding-left:5px; padding-top:3px"><input type="text" id="descriptionFilterInput" /></td>
								</tr>
								<tr>
									<td colspan="2"><b>Filter by severity:</b></td>
									<td style="padding-left:5px; padding-top:3px"><input type="text" id="severityFilterInput" /></td>
								</tr>
								<tr>
									<td colspan="2"><b>Filter by location:</b></td>
									<td style="padding-left:5px; padding-top:3px"><input type="text" id="locationFilterInput"/></td>
								</tr>
								<tr>
									<td colspan="2"><b>Filter by parameter:</b></td>
									<td style="padding-left:5px; padding-top:3px"><input type="text" id="parameterFilterInput" /></td>
								</tr>
								<tr>
									<td><a href="#" onClick="Filter();">Filter</a>&nbsp;|&nbsp;</td>
									<td><a href="#" onClick="ClearFilters();">Clear Filters</a>&nbsp;|&nbsp;</td>
									<td><a href="#" onClick="toggleFilters(false);">Hide Filters</a></td>
								</tr>
							</table>
						</div>
						<div id="showFilters" style="display:none;">
							<a href="#" onClick="toggleFilters(true);">Show Filters</a>
						</div>
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
		<fieldset>
		<br/>
			<div class="buttonGroup">			
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
			<c:choose>
				<c:when test="${ empty application.vulnerabilities }">
						<tr class="bodyRow">
							<td colspan="7" style="text-align:center;"> No Vulnerabilities found.</td>
						</tr>
				</c:when>
				<c:otherwise>
					<c:forEach var="vuln" items="${ application.vulnerabilities }">
						<tr class="bodyRow">
							<td><c:out value="${ vuln.defect.nativeId }"/></td>
							<td><c:out value="${ vuln.isOpen }"/></td>
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
							<td style="padding-left:80px">
							<c:choose>
								<c:when test="${ empty vuln.defect.id }">
									<form:checkbox path="vulnerabilityIds" value="${ vuln.id }"/>									
								</c:when>
								<c:otherwise>
									<form:checkbox path="vulnerabilityIds" value="${ vuln.id }" checked="checked" disabled="true" />
								</c:otherwise>
							</c:choose>
							</td>
						</tr>
					</c:forEach>
				</c:otherwise>
			</c:choose>
					</tbody>
					<tfoot>
						<tr class="footer">
							<td colspan="7" class="pagination" style="text-align:right"></td>
						</tr>
					</tfoot>
				</table>
			</div>
			
			<input type="submit" value="Add Defect">
		</fieldset>
	</form:form>
	</div>
</body>
<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Undo False Positives</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
	<spring:url value="table" var="tableUrl" />
	<script type="text/javascript">
	window.onload = function()
    {
		toggleFilters(false, '#toReplace', '${ tableUrl }');
		toggleFilters(true, '#toReplace', '${ tableUrl }');
    };
    </script>
</head>

<body id="apps">
	<h2>False Positives</h2>
	<spring:url value="/organizations/{orgId}/applications/{appId}"
		var="appUrl">
		<spring:param name="orgId" value="${ application.organization.id }" />
		<spring:param name="appId" value="${ application.id }" />
	</spring:url>
	<h2>
		<a href="${ fn:escapeXml(appUrl) }"><c:out
				value="${ application.name }" /></a>
	</h2>

	<c:if test="${ not empty error }">
		<center class="errors">
			<c:out value="${ error }" />
		</center>
	</c:if>

	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Team:</td>
				<td class="inputValue"><c:out
						value="${ application.organization.name }" /></td>
				<td class="label">Defect Tracker:</td>
				<c:choose>
					<c:when test="${ empty application.defectTracker }">
						<td class="inputValue">No Defect Tracker found. </td>
					</c:when>
					<c:otherwise>
						<td class="inputValue"><c:out
								value="${application.defectTracker.defectTrackerType.name }" />
							<em>(<a
								href="<spring:url value="${ application.defectTracker.url }" />"><c:out
										value="${ application.defectTracker.url }" /></a>)
						</em></td>
						<td class="label">Product:</td>
						<td class="inputValue"><c:out
								value="${ application.projectName}" /></td>
					</c:otherwise>
				</c:choose>
			</tr>
			<tr>
				<td class="label">URL:</td>
				<td class="inputValue"><a
					href="<spring:url value="${ application.url }" />"> <c:out
							value="${ application.url }" />
				</a></td>
				<td class="label">WAF:</td>
				<c:choose>
					<c:when test="${ empty application.waf }">
						<td class="inputValue">No WAF found. </td>
					</c:when>
					<c:otherwise>
						<td class="inputValue"><c:out
								value="${ application.waf.wafType.name }" /> <em>(<c:out
									value="${ application.waf.name }" />)
						</em></td>
					</c:otherwise>
				</c:choose>
			</tr>
		</tbody>
	</table>
	<br />

	<div class="section">
		<spring:url value="" var="emptyUrl" />
		<form:form modelAttribute="falsePositiveModel" method="post"
			action="${ fn:escapeXml(emptyUrl) }">
			<table class="dataTable">
				<tbody>
					<tr>
						<td rowspan="4" style="padding-bottom: 10px; vertical-align: top">
							<div class="buttonGroup" id="vulnerabilityFilters">
								<table style="margin: 0px; padding: 0px; margin-left: auto;">
									<tr>
										<td colspan="2"><b>Vulnerability Name:</b></td>
										<td style="padding-left: 5px; padding-top: 3px"><input
											class="disableSubmitOnEnter" type="text"
											id="descriptionFilterInput" /></td>
									</tr>
									<tr>
										<td colspan="2"><b>Severity:</b></td>
										<td style="padding-left: 5px; padding-top: 3px"><input
											class="disableSubmitOnEnter" type="text"
											id="severityFilterInput" /></td>
									</tr>
									<tr>
										<td colspan="2"><b>Location:</b></td>
										<td style="padding-left: 5px; padding-top: 3px"><input
											class="disableSubmitOnEnter" type="text"
											id="locationFilterInput" /></td>
									</tr>
									<tr>
										<td colspan="2"><b>Parameter:</b></td>
										<td style="padding-left: 5px; padding-top: 3px"><input
											class="disableSubmitOnEnter" type="text"
											id="parameterFilterInput" /></td>
									</tr>
									<tr>
										<td><a
											href="javascript:filter('#toReplace', '${ tableUrl }');">Filter</a>&nbsp;|&nbsp;</td>
										<td><a
											href="javascript:clearFilters('#toReplace', '${ tableUrl }');">Clear
												Filters</a>&nbsp;|&nbsp;</td>
										<td><a
											href="javascript:toggleFilters(false, '#toReplace', '${ tableUrl }');">Hide
												Filters</a></td>
									</tr>
								</table>
							</div>
							<div id="showFilters" style="display: none;">
								<a href="javascript:toggleFilters(true, '#toReplace', '${ tableUrl }');">Show
									Filters</a>
							</div> <spring:url value="table" var="tableUrl" /> <script>
								toggleFilters(true, '#toReplace', '${ tableUrl }');
							</script>
						</td>
					</tr>
				</tbody>
			</table>

			<div id="toReplace">

				<table class="formattedTable sortable filteredTable" id="anyid">
					<thead>
						<tr>
							<th class="first">If Merged</th>
							<th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 1)">Vulnerability
								Name</th>
							<th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 2)">Severity</th>
							<th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 3)">Path</th>
							<th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 4)">Parameter</th>
							<th>Defect</th>
							<th>Defect Status</th>
							<th>WAF Rule</th>
							<th class="unsortable">WAF Events</th>
							<th class="last unsortable">Select All <input
								type="checkbox" id="chkSelectAll"
								onclick="ToggleCheckboxes('anyid',9)"></th>
						</tr>
					</thead>
					<tbody>
						<tr class="bodyRow">
							<td colspan="10" style="text-align: center;">Loading
								Vulnerabilities.</td>
						</tr>
					</tbody>
					<tfoot>
						<tr class="footer">
							<td colspan="10" style="text-align: right"><input
								type="submit" value="Unmark as False Positives">
							</td>
						</tr>
					</tfoot>
				</table>

			</div>
			<input type="submit" value="<c:out value="${ buttonText }"/>">
			<span style="padding-left: 10px"><a
				href="${ fn:escapeXml(appUrl) }">Cancel</a></span>
		</form:form>
	</div>
</body>
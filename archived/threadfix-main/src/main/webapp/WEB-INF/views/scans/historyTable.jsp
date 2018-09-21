<%@ include file="/common/taglibs.jsp"%>

<body>
	<spring:url value="/login.jsp" var="loginUrl" />
	<span id="ajaxVulnTable"></span>
	<spring:url value="/scans/table" var="tableUrl" />
	<c:if test="${ numScans > 100 }">
		<div style="padding-bottom: 8px" ng-non-bindable>
			<c:if test="${ page > 4 }">
				<a id="firstPage"
					href="javascript:refillElement('#toReplace', '${tableUrl}', 1, '<c:out value="${ loginUrl }"/>')">First</a>
			</c:if>
			<c:if test="${ page >= 4 }">
				<a id="page-3"
					href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page - 3 }, '<c:out value="${ loginUrl }"/>')"><c:out
						value="${ page - 3 }" /></a>
			</c:if>
			<c:if test="${ page >= 3 }">
				<a id="page-2"
					href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page - 2 }, '<c:out value="${ loginUrl }"/>')"><c:out
						value="${ page - 2 }" /></a>
			</c:if>
			<c:if test="${ page >= 2 }">
				<a id="page-1"
					href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page - 1 }, '<c:out value="${ loginUrl }"/>')"><c:out
						value="${ page - 1 }" /></a>
			</c:if>
			<c:out value="${ page }" />
			<c:if test="${ page < numPages }">
				<a id="page+1"
					href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page + 1 }, '<c:out value="${ loginUrl }"/>')"><c:out
						value="${ page + 1 }" /></a>
			</c:if>
			<c:if test="${ page < numPages - 1 }">
				<a id="page+2"
					href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page + 2 }, '<c:out value="${ loginUrl }"/>')"><c:out
						value="${ page + 2 }" /></a>
			</c:if>
			<c:if test="${ page < numPages - 2 }">
				<a id="page+3"
					href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page + 3 }, '<c:out value="${ loginUrl }"/>')"><c:out
						value="${ page + 3 }" /></a>
			</c:if>
			<c:if test="${ page < numPages - 3 }">
				<a id="lastPage"
					href="javascript:refillElement('#toReplace', '${tableUrl}', ${ numPages }, '<c:out value="${ loginUrl }"/>')">Last
					(<c:out value="${ numPages }" />)
				</a>
			</c:if>
			<input id="pageInput" class="refillElementOnEnter" type="text"
				id="pageInput" /> <a id="goToPageLink"
				href="javascript:refillElementDropDownPage('#toReplace', '${ tableUrl }', '<c:out value="${ loginUrl }"/>')">Go
				to page</a>
		</div>
	</c:if>

	<table class="table" style="table-layout:fixed;">
		<thead>
			<tr>
				<th style="width: 70px" class="long">Scan Date</th>
				<th style="text-align: left;width:130px;">Application</th>
				<th style="text-align: left;width:130px;" class="first">Team</th>
				<th style="width:90px;">Scanner</th>
				<th style="width:50px;">Total Vulns</th>
				<th style="width:40px;">Hidden</th>
				<th style="width:45px;">Critical</th>
				<th style="width:30px;">High</th>
				<th style="width:45px;">Medium</th>
				<th style="width:25px;">Low</th>
				<th style="width:35px;">Info</th>
				<th></th>
			</tr>
		</thead>
		<tbody id="wafTableBody">
			<c:if test="${ empty scanList }">
				<tr class="bodyRow">
					<td colspan="11" style="text-align: center;">No scans found.</td>
				</tr>
			</c:if>
			<c:forEach var="scan" items="${ scanList }" varStatus="status">
				<tr class="bodyRow" ng-non-bindable>
					<td>
						<fmt:formatDate value="${ scan.importTime.time }" type="both" dateStyle="short"
								timeStyle="short" />
					</td>
					<td id="application${ status.count }"><spring:url
							value="/organizations/{teamId}/applications/{appId}" var="appUrl">
							<spring:param name="teamId"
								value="${ scan.application.organization.id }" />
							<spring:param name="appId" value="${ scan.application.id }" />
							</spring:url> 
							<div style="word-wrap: break-word;max-width:130px;text-align:left;"> <a href="<c:out value="${ appUrl }"/>">
								<c:out	value="${ scan.application.name }" />
							</a></div></td>
					<td id="team${ status.count }"><spring:url
							value="/organizations/{teamId}" var="teamUrl">
							<spring:param name="teamId"
								value="${ scan.application.organization.id }" />
							</spring:url> 
							<div style="word-wrap: break-word;max-width:130px;text-align:left;"> <a href="<c:out value="${ teamUrl }"/>">
								<c:out value="${ scan.application.organization.name }" />
							</a></div></td>
					<td id="channelType${ status.count }"><c:out
							value="${ scan.applicationChannel.channelType.name }" /></td>
					<td style="text-align: center" id="numTotalVulnerabilities${ status.count }">
						<c:out value="${ scan.numberTotalVulnerabilities }" />
					</td>
					<td style="text-align: center" id="numHiddenVulnerabilities${ status.count }">
						<c:out value="${ scan.numberHiddenVulnerabilities }" />
					</td>
					<td style="text-align: center" id="numCriticalVulnerabilities${ status.count }">
						<c:out value="${ scan.numberCriticalVulnerabilities }" />
					</td>
					<td style="text-align: center" id="numHighVulnerabilities${ status.count }">
						<c:out value="${ scan.numberHighVulnerabilities }" />
					</td>
					<td style="text-align: center" id="numMediumVulnerabilities${ status.count }">
						<c:out value="${ scan.numberMediumVulnerabilities }" />
					</td>
					<td style="text-align: center" id="numLowVulnerabilities${ status.count }">
						<c:out value="${ scan.numberLowVulnerabilities }" />
					</td>
					<td style="text-align: center" id="numInfoVulnerabilities${ status.count }">
						<c:out value="${ scan.numberInfoVulnerabilities }" />
					</td>
					<td>
						<spring:url value="/organizations/{teamId}/applications/{appId}/scans/{scanId}" var="scanUrl">
							<spring:param name="teamId" value="${ scan.application.organization.id }" />
							<spring:param name="appId" value="${ scan.application.id }" />
							<spring:param name="scanId" value="${ scan.id }" />
						</spring:url> 
						<a id="importTime${ status.count }" href="${ fn:escapeXml(scanUrl) }"> 
							View Scan
						</a>
					</td>
				</tr>
			</c:forEach>
		</tbody>
	</table>
	<script>
		$('.disableSubmitOnEnter').keypress(function(e) {
			if (e.which == 13)
				return false;
		});
		$('.refillElementOnEnter').keypress(
				function(e) {
					if (e.which == 13) {
						refillElementDropDownPage('#toReplace',
								'<c:out value="${ tableUrl }"/>',
								'<c:out value="${ loginUrl }"/>');
						return false;
					}
				});
	</script>

</body>
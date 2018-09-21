<%@ include file="/common/taglibs.jsp"%>

<head>
	<title ng-non-bindable><c:out value="${ application.name }"/></title>
</head>

<body id="apps">
	<h2 ng-non-bindable><c:out value="${ application.name }"/></h2>
	
	<div id="helpText">
		This page lists all of the scans that have been uploaded to this Application.
	</div>
	
	<h3>Application Scans</h3>
	<table class="table table-striped">
		<thead>
			<tr>
				<th class="first">Channel</th>
				<th class="long">Scan Date</th>
				<c:if test="${ not canUploadScans }">
					<th class="short last">Total Vulns</th>
				</c:if>
				<c:if test="${ canUploadScans }">
					<th class="short">Total Vulns</th>
					<th class="medium last">Delete Scan</th>
				</c:if>
			</tr>
		</thead>
		<tbody id="wafTableBody">
		<c:if test="${ empty application.scans }">
			<tr class="bodyRow">
				<td colspan="4" style="text-align:center;">No scans found.</td>
			</tr>
		</c:if>
		<c:forEach var="scan" items="${ application.scans }" varStatus="status">
			<tr class="bodyRow">
				<td id="channelType${ status.count }" ng-non-bindable><c:out value="${ scan.applicationChannel.channelType.name }"/></td>
				<td>
			        <spring:url value="scans/{scanId}" var="detailUrl">
                        <spring:param name="scanId" value="${ scan.id }"/>
                       </spring:url>
                       <a id="importTime${ status.count }" href="${ fn:escapeXml(detailUrl) }">
				        <fmt:formatDate value="${ scan.importTime.time }" type="both" dateStyle="short" timeStyle="short"/>
				    </a>
				</td>
				<td id="numTotalVulnerabilities${ status.count }" ng-non-bindable><c:out value="${ scan.numberTotalVulnerabilities }"/></td>
				<c:if test="${ canUploadScans }">
				<td>
					<spring:url value="scans/{scanId}/delete" var="deleteUrl">
	                    <spring:param name="scanId" value="${ scan.id }"/>
	                </spring:url>
	                <form:form method="post" action="${ fn:escapeXml(deleteUrl) }" >
	                    <input onclick="return confirm('Are you sure you want to delete this scan and all of its results? This will also delete any WAF rules and defects associated with orphaned vulnerabilities.')" id="deleteScanButton" type="submit" value="Delete Scan" />
                    </form:form>
				</td>
				</c:if>
			</tr>
		</c:forEach>
			<tr class="footer">
				<td colspan="4" class="last pagination" style="text-align:right"></td>
			</tr>
		</tbody>
	</table>

     <spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
		<spring:param name="orgId" value="${ application.organization.id }" />
		<spring:param name="appId" value="${ application.id }" />
	</spring:url>
    <a id="backToApplicationLink" href="${ fn:escapeXml(appUrl) }" ng-non-bindable>Back to Application <c:out value="${ application.name }"/></a>
</body>

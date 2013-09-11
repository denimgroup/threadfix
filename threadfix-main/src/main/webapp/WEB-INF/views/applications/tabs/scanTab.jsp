<%@ include file="/common/taglibs.jsp"%>

<table class="table table-striped">
	<thead>
		<tr>
			<th class="first">Channel</th>
			<th>Scan Date</th>
			<c:if test="${ not canUploadScans }">
				<th>Total Vulns</th>
			</c:if>
			<c:if test="${ canUploadScans }">
				<th style="text-align:center">Total Vulns</th>
				<th style="text-align:center">Hidden Vulns</th>
				<th class="medium"></th>
			</c:if>
			<th class="medium"></th>
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
			<td id="channelType${ status.count }"><c:out value="${ scan.applicationChannel.channelType.name }"/></td>
			<td>
				<fmt:formatDate value="${ scan.importTime.time }" type="both" dateStyle="short" timeStyle="short"/>
			</td>
			<td style="text-align:center" id="numTotalVulnerabilities${ status.count }">
				<c:out value="${ scan.numberTotalVulnerabilities }"/>
			</td>
			<td style="text-align:center" id="numHiddenVulnerabilities${ status.count }">
				<c:out value="${ scan.numberHiddenVulnerabilities }"/>
			</td>
			<c:if test="${ canUploadScans }">
			<td>
                <a class="btn btn-danger scanDelete" data-delete-form="deleteForm${ scan.id }">Delete Scan</a>
				<spring:url value="/organizations/{orgId}/applications/{appId}/scans/{scanId}/delete" var="deleteUrl">
					<spring:param name="orgId" value="${ scan.application.organization.id }"/>
					<spring:param name="appId" value="${ scan.application.id }"/>
					<spring:param name="scanId" value="${ scan.id }"/>
				</spring:url>
				<form id="deleteForm${ scan.id }" method="POST" action="${ fn:escapeXml(deleteUrl) }"></form>
			</td>
			<td>
                <spring:url value="/organizations/{orgId}/applications/{appId}/scans/{scanId}" var="scanUrl">
					<spring:param name="orgId" value="${ scan.application.organization.id }"/>
					<spring:param name="appId" value="${ scan.application.id }"/>
					<spring:param name="scanId" value="${ scan.id }"/>
				</spring:url>
				<a href="<c:out value="${ scanUrl }"/>">View Scan</a>
			</td>
			</c:if>
		</tr>
	</c:forEach>
	</tbody>
</table>

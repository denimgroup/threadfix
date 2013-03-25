<%@ include file="/common/taglibs.jsp"%>

<table class="table auto table-striped">
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
			<td id="channelType${ status.count }"><c:out value="${ scan.applicationChannel.channelType.name }"/></td>
			<td>
		        <spring:url value="/organizations/{orgId}/applications/{appId}/scans/{scanId}" var="detailUrl">
                       <spring:param name="orgId" value="${ scan.application.organization.id }"/>
                       <spring:param name="appId" value="${ scan.application.id }"/>
                       <spring:param name="scanId" value="${ scan.id }"/>
                </spring:url>
                      <a id="importTime${ status.count }" href="${ fn:escapeXml(detailUrl) }">
			        <fmt:formatDate value="${ scan.importTime.time }" type="both" dateStyle="short" timeStyle="short"/>
			    </a>
			</td>
			<td id="numTotalVulnerabilities${ status.count }"><c:out value="${ scan.numberTotalVulnerabilities }"/></td>
			<c:if test="${ canUploadScans }">
			<td>
                <spring:url value="/organizations/{orgId}/applications/{appId}/scans/{scanId}/delete" var="deleteUrl">
                       <spring:param name="orgId" value="${ scan.application.organization.id }"/>
                       <spring:param name="appId" value="${ scan.application.id }"/>
                       <spring:param name="scanId" value="${ scan.id }"/>
                </spring:url>
                <form:form method="post" action="${ fn:escapeXml(deleteUrl) }" >
                    <input onclick="return confirm('Are you sure you want to delete this scan and all of its results? This will also delete any WAF rules and defects associated with orphaned vulnerabilities.')" id="deleteScanButton" type="submit" value="Delete Scan" />
                </form:form>
			</td>
			</c:if>
		</tr>
	</c:forEach>
	</tbody>
</table>

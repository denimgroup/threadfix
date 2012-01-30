<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/></title>
</head>

<body id="apps">
	<h2><c:out value="${ application.name }"/></h2>
	
	<div id="helpText">
		This page lists all of the scans that have been uploaded to this Application.
	</div>
	
	<h3>Application Scans</h3>
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="first">Channel</th>
				<th class="long">Scan Date</th>
				<th class="short last">Total Vulns</th>
			</tr>
		</thead>
		<tbody>
		<c:if test="${ empty application.scans }">
			<tr class="bodyRow">
				<td colspan="3" style="text-align:center;">No scans found.</td>
			</tr>
		</c:if>
		<c:forEach var="scan" items="${ application.scans }">
			<tr class="bodyRow">
				<td><c:out value="${ scan.applicationChannel.channelType.name }"/></td>
				<td>
			        <spring:url value="scans/{scanId}" var="detailUrl">
                        <spring:param name="scanId" value="${ scan.id }"/>
                       </spring:url>
                       <a href="${ fn:escapeXml(detailUrl) }">
				        <fmt:formatDate value="${ scan.importTime.time }" type="both" dateStyle="short" timeStyle="short"/>
				    </a>
				</td>
				<td><c:out value="${ scan.numberTotalVulnerabilities}"/></td>
			</tr>
		</c:forEach>
			<tr class="footer">
				<td colspan="3" class="last pagination" style="text-align:right"></td>
			</tr>
		</tbody>
	</table>

     <spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
		<spring:param name="orgId" value="${ application.organization.id }" />
		<spring:param name="appId" value="${ application.id }" />
	</spring:url>
    <a href="${ fn:escapeXml(appUrl) }">Back to Application <c:out value="${ application.name }"/></a>
</body>
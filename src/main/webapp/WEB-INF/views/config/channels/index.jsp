<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Channels</title>
</head>

<body id="config">
	<h2>Channels</h2>
	<br/>
	<a href="<spring:url value="/configuration/channels/new" />">Add Channel</a>
	<br/>
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="medium first">Organization</th>
				<th class="medium">Application</th>
				<th class="long last">Channel Type</th>
			</tr>
		</thead>
		<tbody>
		<c:if test="${ hasActiveApps }">
			<c:forEach var="appChannel" items="${ applicationChannelList }">
				<c:if test="${ appChannel.application.active }">
				<tr class="bodyRow">
					<td>
						<spring:url value="/organizations/{orgId}" var="orgUrl">
							<spring:param name="orgId" value="${ appChannel.application.organization.id }" />
						</spring:url>
						<a href="${ fn:escapeXml(orgUrl) }">
							<c:out value="${ appChannel.application.organization.name }"/>
						</a>
					</td>
					<td>
						<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
							<spring:param name="orgId" value="${ appChannel.application.organization.id }"/>
							<spring:param name="appId" value="${ appChannel.application.id }"/>
						</spring:url>
						<a href="${ fn:escapeXml(appUrl) }"><c:out value="${ appChannel.application.name }"/></a>
					</td>
					<td>
						<c:out value="${ appChannel.channelType.name }"/>
					</td>
				</tr>
				</c:if>
			</c:forEach>
		</c:if>
		<c:if test="${ not hasActiveApps }">
			<tr class="bodyRow">
				<td colspan="3" style="text-align:center;">No channels found.</td>
			</tr>
		</c:if>
		</tbody>
	</table>
</body>
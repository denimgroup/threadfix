<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Scan Agent Task</title>
</head>

<body>

<spring:url value="/organizations/{orgId}" var="orgUrl">
    <spring:param name="orgId" value="${ scanQueueTask.application.organization.id }" />
</spring:url>
<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
    <spring:param name="orgId" value="${ scanQueueTask.application.organization.id }" />
    <spring:param name="appId" value="${ scanQueueTask.application.id }" />
</spring:url>

<ul class="breadcrumb">
    <li><a href="<spring:url value="/organizations"/>">Applications Index</a> <span class="divider">/</span></li>
    <li><a href="${ fn:escapeXml(orgUrl) }">Team: <c:out value="${ scanQueueTask.application.organization.name }"/></a> <span class="divider">/</span></li>
    <li><a href="${ fn:escapeXml(appUrl) }">Application: <c:out value="${ scanQueueTask.application.name }"/></a><span class="divider">/</span></li>
    <li class="active">Scan Agent Task ID <c:out value="${scanQueueTask.id}" /></li>
</ul>

	<h2>Scan Agent Task</h2>
	
	<div id="helpText">
		This shows detail about a specific queued scan.<br/>
	</div>
	
	<div id="tableDiv">
	
		<table class="table">
			<thead>
				<tr>
					<th>Timestamp</th>
					<th>Message</th>
				</tr>
			</thead>
			<tbody>
				<c:forEach items="${scanQueueTask.scanStatuses}" var="scanStatus"> 
					<tr>
						<td><fmt:formatDate value="${ scanStatus.timestamp }" type="both" dateStyle="short" timeStyle="short" /></td>
						<td><pre><c:out value="${scanStatus.message}" /></pre></td>					
					</tr>
				</c:forEach>
			</tbody>

		</table>
	</div>
	
	<br/>
	
</body>

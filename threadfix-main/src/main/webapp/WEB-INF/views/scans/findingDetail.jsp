<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Finding Details</title>
	<meta name="heading" content="<fmt:message key='mainMenu.heading'/>" />
</head>

<body id="apps">

	<spring:url value="/organizations/{orgId}" var="orgUrl">
		<spring:param name="orgId" value="${ finding.scan.application.organization.id }" />
	</spring:url>
	<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
		<spring:param name="orgId" value="${ finding.scan.application.organization.id }" />
		<spring:param name="appId" value="${ finding.scan.application.id }" />
	</spring:url>
	<spring:url value="/organizations/{orgId}/applications/{appId}/scans/{scanId}" var="scanUrl">
		<spring:param name="orgId" value="${ finding.scan.application.organization.id }" />
		<spring:param name="appId" value="${ finding.scan.application.id }" />
		<spring:param name="scanId" value="${ finding.scan.id }" />
	</spring:url>

	<ul class="breadcrumb">
	    <li><a href="<spring:url value="/teams"/>">Applications Index</a><span class="divider">/</span></li>
	    <li><a href="${ fn:escapeXml(orgUrl) }" ng-non-bindable>Team <c:out value="${ finding.scan.application.organization.name }"/></a> <span class="divider">/</span></li>
	    <li><a href="${ fn:escapeXml(appUrl) }" ng-non-bindable>Application <c:out value="${ finding.scan.application.name }"/></a><span class="divider">/</span></li>
	    <li><a href="${ fn:escapeXml(scanUrl) }" ng-non-bindable><fmt:formatDate value="${ finding.scan.importTime.time }" type="both" dateStyle="short" timeStyle="short"/> <c:out value="${ fn:escapeXml(finding.scan.applicationChannel.channelType.name) }"/> Scan</a><span class="divider">/</span></li>
	    <li class="active">Finding ${ fn:escapeXml(finding.id) }</li>
    </ul>

	<%@ include file="/WEB-INF/views/scans/finding/detail.jsp" %>
</body>

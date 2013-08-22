<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Vulnerability Filters</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/vulnerability_filters.js"></script>
</head>

<body>
	<c:choose>
		<c:when test="${ type == 'Application' }">
			<h2>Application <c:out value="${ application.name }"/> Vulnerability Filters</h2>
		</c:when>
		<c:when test="${ type == 'Organization' }">
			<h2>Team <c:out value="${ organization.name }"/> Vulnerability Filters</h2>
		</c:when>
		<c:otherwise>
			<h2>Global Vulnerability Filters</h2>
		</c:otherwise>
	</c:choose>
	
	<div id="helpText">
		ThreadFix Vulnerability Filters are used to sort data.<br/>
	</div>
	
	<c:choose>
		<c:when test="${ type == 'Application' }">
			<spring:url value="/organizations/{orgId}/applications/{appId}" var="backUrl">
				<spring:param name="orgId" value="${application.organization.id}"/>
				<spring:param name="appId" value="${application.id}"/>
			</spring:url>
		</c:when>
		<c:when test="${ type == 'Organization' }">
			<spring:url value="/organizations/{orgId}" var="backUrl">
				<spring:param name="orgId" value="${organization.id}"/>
			</spring:url>
		</c:when>
	</c:choose>
	
	<c:if test="${ not empty backUrl }">
		<a id="backButton" class="btn" href="${ backUrl }">Back</a>
	</c:if>
	
	<div id="tableDiv">
		<%@ include file="/WEB-INF/views/filters/table.jsp" %>
	</div>
</body>

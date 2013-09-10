<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Manage Filters</title>
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
	
	<c:if test="${ type != 'Global' }">
		
		<c:choose>
			<c:when test="${ type == 'Application' }">
				<spring:url value="/organizations/{orgId}/applications/{appId}" var="backUrl">
					<spring:param name="orgId" value="${severityFilter.application.organization.id}"/>
					<spring:param name="appId" value="${severityFilter.application.id}"/>
				</spring:url>
			</c:when>
			<c:when test="${ type == 'Organization' }">
				<spring:url value="/organizations/{orgId}" var="backUrl">
					<spring:param name="orgId" value="${severityFilter.organization.id}"/>
				</spring:url>
			</c:when>
		</c:choose>
		
		<c:if test="${ not empty backUrl }">
			<a id="backButton" class="btn" href="${ backUrl }">Back</a>
		</c:if>
		
		<c:if test="${ type == 'Application' }">
			<spring:url value="/organizations/{orgId}/applications/{appId}/filters/tab" var="appTabUrl">
				<spring:param name="orgId" value="${severityFilter.application.organization.id}"/>
				<spring:param name="appId" value="${severityFilter.application.id}"/>
			</spring:url>
			<spring:url value="/organizations/{orgId}/filters/tab" var="orgTabUrl">
				<spring:param name="orgId" value="${severityFilter.application.organization.id}"/>
			</spring:url>
		</c:if>
		<c:if test="${ type == 'Organization' }">
			<spring:url value="/organizations/{orgId}" var="orgTabUrl">
				<spring:param name="orgId" value="${severityFilter.organization.id}"/>
			</spring:url>
		</c:if>
		<spring:url value="/configuration/filters/tab" var="globalTabUrl"/>
		
		<ul class="nav nav-tabs margin-top">
			<c:if test="${ not empty appTabUrl }">
				<li class="<c:if test="${ type == 'Application' }">active</c:if> pointer">
					<a data-toggle="tab" class="filterTab" id="applicationTabLink" href="#" data-url="<c:out value="${ appTabUrl }"/>">
						Application Filters
					</a>
				</li>
			</c:if>
			<c:if test="${ not empty orgTabUrl }">
				<li class="<c:if test="${ type == 'Organization' }">active</c:if> pointer">
					<a data-toggle="tab" class="filterTab" id="teamTabLink" href="#" data-url="<c:out value="${ orgTabUrl }"/>">
						Team Filters
					</a>
				</li>
			</c:if>
			<li class="<c:if test="${ type == 'Global' }">active</c:if> pointer">
				<a data-toggle="tab" class="filterTab" id="globalTabLink" href="#" data-url="<c:out value="${ globalTabUrl }"/>">
					Global Filters
				</a>
			</li>
		</ul>
	</c:if>
	
    <div id="tabsDiv">
    	<%@ include file="/WEB-INF/views/filters/tab.jsp" %>
    </div>
	
</body>

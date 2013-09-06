<%@ include file="/common/taglibs.jsp"%>

<c:if test="${ numVulns != 0 }"> 

	<spring:url value="/organizations/{orgId}/applications/{appId}/filters" var="vulnFiltersUrl">
		<spring:param name="orgId" value="${ application.organization.id }"/>
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
	
	<spring:url value="{appId}/hidden/table" var="tableUrl">
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>

	<span>
		<a class="btn" id="viewFiltersButton" href="${ fn:escapeXml(vulnFiltersUrl) }">View Vulnerability Filters</a>
	</span>
	
	<span style="float:right">
		<a class="btn" id="expandAllVulns">Expand All</a>
		<a class="btn" id="collapseAllVulns">Collapse All</a>
	</span>
	
	<%@ include file="/WEB-INF/views/applications/tabs/filter.jspf" %>	
	
	<%@ include file="/WEB-INF/views/applications/tabs/defaultTableDiv.jspf" %>

</c:if>

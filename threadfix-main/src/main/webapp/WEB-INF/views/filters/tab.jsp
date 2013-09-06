<%@ include file="/common/taglibs.jsp"%>

<a id="createNewKeyModalButton" href="#newFilterModalDiv" role="button" class="btn" data-toggle="modal">Create New Filter</a>
	
<h3>
<c:if test="${ type == 'Organization' }"> 
	Team
</c:if>
<c:if test="${ type != 'Organization' }">
	<c:out value="${ type }"/>
</c:if>

Vulnerability Filters</h3>
	
<div id="tableDiv">
	<%@ include file="/WEB-INF/views/filters/table.jsp" %>
</div>

<h3>
<c:if test="${ type == 'Organization' }"> 
	Team
</c:if>
<c:if test="${ type != 'Organization' }">
	<c:out value="${ type }"/>
</c:if>

Severity Filters</h3>

<%@ include file="/WEB-INF/views/filters/severityFilterForm.jsp" %>
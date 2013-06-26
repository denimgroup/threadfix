<%@ include file="/common/taglibs.jsp"%>

<c:if test="${ numVulns != 0 }"> 

<spring:url value="{appId}/falsepositives/mark" var="markFPUrl">
      	<spring:param name="appId" value="${ application.id }" />
  	</spring:url>
<form:form modelAttribute="falsePositiveModel" method="post" action="${ fn:escapeXml(markFPUrl) }">

<spring:url value="{appId}/falsePositives/table" var="tableUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>

<spring:url value="{appId}/falsePositives/unmark" var="fpUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>

<c:if test="${ canModifyVulnerabilities }">
	<a class="btn" id="markFalsePositiveButton" onclick="javascript:submitVulnTableOperation('${ fpUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark Not False Positive</a>
</c:if>

<span style="float:right">
	<a class="btn" id="expandAllVulns">Expand All</a>
	<a class="btn" id="collapseAllVulns">Collapse All</a>
</span>

<%@ include file="/WEB-INF/views/applications/tabs/filter.jspf" %>

<%@ include file="/WEB-INF/views/applications/tabs/defaultTableDiv.jspf" %>

<c:if test="${ canModifyVulnerabilities }">
	<a class="btn" id="markFalsePositiveButton" onclick="javascript:submitVulnTableOperation('${ fpUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark Not False Positive</a>
</c:if>

</form:form>

</c:if>

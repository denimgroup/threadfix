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
	<a class="btn" id="markFalsePositiveButton" onclick="javascript:submitVulnTableOperation('${ fpUrl }', '#submitDefectFormDiv', '#teamTable');return false;" href="#">Mark Not False Positive</a>
</c:if>

<%@ include file="/WEB-INF/views/applications/tabs/filter.jspf" %>

<%@ include file="/WEB-INF/views/applications/tabs/defaultTableDiv.jspf" %>

<c:if test="${ canModifyVulnerabilities }">
	<a class="btn" id="markFalsePositiveButton" onclick="javascript:submitVulnTableOperation('${ fpUrl }', '#submitDefectFormDiv', '#teamTable');return false;" href="#">Mark Not False Positive</a>
</c:if>

</form:form>

</c:if>

<%@ include file="/common/taglibs.jsp"%>

<c:if test="${ numVulns != 0 }"> 

<spring:url value="{appId}/falsepositives/mark" var="markFPUrl">
      	<spring:param name="appId" value="${ application.id }" />
  	</spring:url>
<form:form modelAttribute="falsePositiveModel" method="post" action="${ fn:escapeXml(markFPUrl) }">

<spring:url value="{appId}/closedVulnerabilities/table" var="tableUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>

<spring:url value="{appId}/table/open" var="openUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>

<spring:url value="{appId}/closed/falsePositives/mark" var="fpUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>

<c:if test="${ canModifyVulnerabilities }">
   	<div id="btnDiv1" class="btn-group">
		<button id="actionButton1" class="btn dropdown-toggle" data-toggle="dropdown" type="button">Action <span class="caret"></span></button>
		<ul class="dropdown-menu">
			<li><a id="markOpenButton" onclick="javascript:submitVulnTableOperation('${ openUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark Open</a></li>
			<li><a id="markFalsePositiveButton" onclick="javascript:submitVulnTableOperation('${ fpUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark False Positive</a></li>
		</ul>
	</div>
</c:if>

<span style="float:right">
	<a class="btn" id="expandAllVulns">Expand All</a>
	<a class="btn" id="collapseAllVulns">Collapse All</a>
</span>

<%@ include file="/WEB-INF/views/applications/tabs/filter.jspf" %>	

<%@ include file="/WEB-INF/views/applications/tabs/defaultTableDiv.jspf" %>

<c:if test="${ canModifyVulnerabilities }">
   	<div id="btnDiv2" class="btn-group">
		<button id="actionButton1" class="btn dropdown-toggle" data-toggle="dropdown" type="button">Action <span class="caret"></span></button>
		<ul class="dropdown-menu">
			<li><a id="markOpenButton" onclick="javascript:submitVulnTableOperation('${ openUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark Open</a></li>
			<li><a id="markFalsePositiveButton" onclick="javascript:submitVulnTableOperation('${ fpUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark False Positive</a></li>
		</ul>
	</div>
</c:if>

</form:form>

</c:if>

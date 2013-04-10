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

<spring:url value="{appId}/falsePositives/mark" var="fpUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>

<c:if test="${ canModifyVulnerabilities }">
   	<div id="btnDiv1" class="btn-group">
		<button id="actionButton1" class="btn dropdown-toggle" type="button">Action <span class="caret"></span></button>
		<ul class="dropdown-menu">
			<li><a id="markOpenButton" onclick="javascript:submitVulnTableOperation('${ openUrl }', '#submitDefectFormDiv', '#teamTable');return false;" href="#">Mark Open</a></li>
			<li><a id="markFalsePositiveButton" onclick="javascript:submitVulnTableOperation('${ fpUrl }', '#submitDefectFormDiv', '#teamTable');return false;" href="#">Mark False Positive</a></li>
		</ul>
	</div>
	<script>
	$("#actionButton1").bind({
		mouseenter : function(e) {
			$("#actionButton1").dropdown('toggle');
		},
		mouseleave : function(e) {
			$("#actionButton1").dropdown('toggle');
		}
	});
	</script>
</c:if>

<%@ include file="/WEB-INF/views/applications/tabs/filter.jspf" %>	

<%@ include file="/WEB-INF/views/applications/tabs/defaultTableDiv.jspf" %>

<c:if test="${ canModifyVulnerabilities }">
   	<div id="btnDiv1" class="btn-group">
		<button id="actionButton1" class="btn dropdown-toggle" type="button">Action <span class="caret"></span></button>
		<ul class="dropdown-menu">
			<li><a id="markOpenButton" onclick="javascript:submitVulnTableOperation('${ openUrl }', '#submitDefectFormDiv', '#teamTable');return false;" href="#">Mark Open</a></li>
			<li><a id="markFalsePositiveButton" onclick="javascript:submitVulnTableOperation('${ fpUrl }', '#submitDefectFormDiv', '#teamTable');return false;" href="#">Mark False Positive</a></li>
		</ul>
	</div>
	<script>
	$("#actionButton1").bind({
		mouseenter : function(e) {
			$("#actionButton1").dropdown('toggle');
		},
		mouseleave : function(e) {
			$("#actionButton1").dropdown('toggle');
		}
	});
	</script>
</c:if>

</form:form>

</c:if>

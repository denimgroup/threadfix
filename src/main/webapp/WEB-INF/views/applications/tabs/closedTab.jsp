<%@ include file="/common/taglibs.jsp"%>

<c:if test="${ numVulns != 0 }"> 

<spring:url value="{appId}/falsepositives/mark" var="markFPUrl">
      	<spring:param name="appId" value="${ application.id }" />
  	</spring:url>
<form:form modelAttribute="falsePositiveModel" method="post" action="${ fn:escapeXml(markFPUrl) }">

<spring:url value="{appId}/closedVulnerabilities/table" var="tableUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>

<%@ include file="/WEB-INF/views/applications/tabs/filter.jspf" %>	

<%@ include file="/WEB-INF/views/applications/tabs/defaultTableDiv.jspf" %>

<c:if test="${ canModifyVulnerabilities }">
   	<div id="btnDiv" class="btn-group">
		<button id="actionButton" class="btn dropdown-toggle" type="button">Action <span class="caret"></span></button>
		<ul class="dropdown-menu">
			<li><a id="markClosedButton" href="#markClosedConfirm">Mark Open</a></li>
			<li><a id="markFalsePositiveButton" href="#markFalsePositiveConfirm">Mark False Positive</a></li>
		</ul>
	</div>
	<script>
	$("#btnDiv").bind({
		mouseenter : function(e) {
			$("#actionButton").dropdown('toggle');
		},
		mouseleave : function(e) {
			$("#actionButton").dropdown('toggle');
		}
	});
	</script>
</c:if>

</form:form>

</c:if>

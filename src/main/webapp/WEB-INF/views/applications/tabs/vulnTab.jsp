<%@ include file="/common/taglibs.jsp"%>

<c:if test="${ not empty application.scans }"> 

<spring:url value="{appId}/falsepositives/mark" var="markFPUrl">
      	<spring:param name="appId" value="${ application.id }" />
  	</spring:url>
<form:form modelAttribute="falsePositiveModel" method="post" action="${ fn:escapeXml(markFPUrl) }">

<spring:url value="{appId}/table" var="tableUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>

<spring:url value="{appId}/table/close" var="closeUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>

<spring:url value="{appId}/falsePositives/mark" var="fpUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>

<c:if test="${ canModifyVulnerabilities }">
   	<div id="btnDiv1" class="btn-group">
		<button id="actionButton1" class="btn dropdown-toggle" type="button">Action <span class="caret"></span></button>
		<ul class="dropdown-menu">
			<c:if test="${ not empty application.defectTracker }">
				<li><a id="submitDefectButton" href="#submitDefectModal" data-toggle="modal">Submit Defect</a></li>
			</c:if>
			<li><a id="markClosedButton" onclick="javascript:submitVulnTableOperation('${ closeUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark Closed</a></li>
			<li><a id="markFalsePositiveButton" onclick="javascript:submitVulnTableOperation('${ fpUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark False Positive</a></li>
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
   	<div id="btnDiv2" class="btn-group">
		<button id="actionButton2" class="btn dropdown-toggle" type="button">Action <span class="caret"></span></button>
		<ul class="dropdown-menu">
			<c:if test="${ not empty application.defectTracker }">
				<li><a id="submitDefectButton" href="#submitDefectModal" data-toggle="modal">Submit Defect</a></li>
			</c:if>
			<li><a id="markClosedButton" onclick="javascript:submitVulnTableOperation('${ closeUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark Closed</a></li>
			<li><a id="markFalsePositiveButton" onclick="javascript:submitVulnTableOperation('${ fpUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark False Positive</a></li>
		</ul>
	</div>
	<script>
	$("#actionButton2").bind({
		mouseenter : function(e) {
			$("#actionButton2").dropdown('toggle');
		},
		mouseleave : function(e) {			
			$("#actionButton2").dropdown('toggle');
		}
	});
	</script>
</c:if>

</form:form>

</c:if>

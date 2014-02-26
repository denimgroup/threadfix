<script type="text/ng-template" id="createDefectTrackerModal.html">

<spring:url value="/organizations/{orgId}/applications/{appId}/getDefectsFromDefectTracker" var="refreshUrl">
	<spring:param name="orgId" value="${ application.organization.id }"/>
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>
<div id="mergeDefectModal" class="modal hide fade" tabindex="-1" style="width:686px;margin-left:-343px;"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div class="modal-header">
		<h4>Merge Defect</h4>
	</div>
	<div data-refresh-url="<c:out value="${ refreshUrl }"/>" id="mergeDefectFormDiv">
		<%@ include file="/WEB-INF/views/defects/mergeDefectForm.jsp" %>
	</div>
</div>
</script>
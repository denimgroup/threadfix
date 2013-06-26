<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/organizations/{orgId}/applications/{appId}/defectSubmission" var="refreshUrl">
	<spring:param name="orgId" value="${ application.organization.id }"/>
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>
<div id="submitDefectModal" class="modal hide fade" tabindex="-1" style="width:686px;margin-left:-343px;"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div class="modal-header">
		<h4>Submit Defect</h4>
	</div>
	<div data-refresh-url="<c:out value="${ refreshUrl }"/>" id="submitDefectFormDiv">
		<%@ include file="/WEB-INF/views/defects/submitDefectForm.jsp" %>
	</div>
</div>

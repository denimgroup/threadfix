<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/configuration/defecttrackers/new" var="newDTUrl"/>
<div id="createDefectTracker" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div class="modal-header">
		<button type="button" class="close" data-dismiss="modal"
			aria-hidden="true">X</button>
		<h4 id="myModalLabel">New Defect Tracker</h4>
	</div>
	<div id="dtFormDiv">
		<%@ include file="/WEB-INF/views/config/defecttrackers/forms/createDTForm.jsp" %>
	</div>
</div>
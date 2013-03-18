<%@ include file="/common/taglibs.jsp"%>

<div id="editDefectTracker${ defectTracker.id }" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div class="modal-header">
		<button type="button" class="close" data-dismiss="modal"
			aria-hidden="true">X</button>
		<h4 id="myModalLabel">Edit Defect Tracker</h4>
	</div>
	<div id="dtFormDiv${defectTracker.id }">
		<%@ include file="/WEB-INF/views/config/defecttrackers/forms/editDTForm.jsp" %>
	</div>
</div>
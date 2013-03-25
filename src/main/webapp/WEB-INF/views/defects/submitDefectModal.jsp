<%@ include file="/common/taglibs.jsp"%>

<div id="submitDefectModal" class="modal hide fade" tabindex="-1" style="width:686px;margin-left:-343px;"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div class="modal-header">
		<button type="button" class="close" data-dismiss="modal"
			aria-hidden="true">X</button>
		<h4>Submit Defect</h4>
	</div>
	<div id="submitDefectFormDiv">
		<%@ include file="/WEB-INF/views/defects/submitDefectForm.jsp" %>
	</div>
</div>
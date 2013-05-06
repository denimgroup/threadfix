<%@ include file="/common/taglibs.jsp"%>

<div id="addManualFindingModal" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div class="modal-header">
		<h4><c:if test="${ finding['new'] }">New</c:if> Finding</h4>
	</div>
	<div id="manualFindingFormDiv">
		<%@ include file="/WEB-INF/views/applications/forms/manualFindingForm.jsp" %>
	</div>
</div>
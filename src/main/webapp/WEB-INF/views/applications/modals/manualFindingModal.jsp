<%@ include file="/common/taglibs.jsp"%>

<a id="addManualFindingModalLink" href="#addManualFindingModal" role="button" class="btn" data-toggle="modal">Add Manual Finding</a>
<div id="addManualFindingModal" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div class="modal-header">
		<h4><c:if test="${ finding['new'] }">New</c:if> Finding</h4>
	</div>
	<div id="manualFindingFormDiv">
		<%@ include file="/WEB-INF/views/applications/forms/manualFindingForm.jsp" %>
	</div>
</div>
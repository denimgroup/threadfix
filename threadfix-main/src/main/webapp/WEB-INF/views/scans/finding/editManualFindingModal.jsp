<%@ include file="/common/taglibs.jsp"%>

<div id="editManualFindingModal${ finding.id }" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true"
		style="width:700px;margin-left:-350px;">
	<div id="manualFindingFormDiv">
		<%@ include file="/WEB-INF/views/scans/finding/editManualFindingForm.jsp" %>
	</div>
</div>

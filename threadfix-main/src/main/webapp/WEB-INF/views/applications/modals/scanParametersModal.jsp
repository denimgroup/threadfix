<%@ include file="/common/taglibs.jsp"%>

<div id="editScanParametersModal" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div class="modal-header">
		<h4 style="text-align:left" id="myModalLabel"><c:out value="${ application.name }"/> Scan Settings</h4>
	</div>
	<div id="scanParametersDiv">
		<%@ include file="/WEB-INF/views/applications/forms/scanParametersForm.jsp" %>
	</div>
</div>

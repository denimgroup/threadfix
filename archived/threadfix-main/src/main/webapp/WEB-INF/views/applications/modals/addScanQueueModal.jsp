<%@ include file="/common/taglibs.jsp"%>

<c:if test="${ canManageApplications && fn:length(scannerTypeList) > 0 }">
	<div style="margin-top:10px;margin-bottom:7px;">
		<a id="addScanQueueLink${ application.id }" href="#addScanQueue${ application.id }" role="button" class="btn" data-toggle="modal">Add New Task</a>
	</div>	
</c:if>

<div id="addScanQueue${ application.id }" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div id="scanFormDiv${ application.id }">
		<%@ include file="/WEB-INF/views/applications/forms/addScanQueueForm.jsp" %>
	</div>
</div>
<%@ include file="/common/taglibs.jsp"%>

<c:if test="${ canManageApplications && fn:length(scannerTypeList) > 0 }">
	<div style="margin-top:10px;margin-bottom:7px;">
		<a id="addScanQueueLink${ application.id }" href="#addScheduledScan${ application.id }" role="button" class="btn" data-toggle="modal">Schedule New Scan</a>
	</div>	
</c:if>

<div id="addScheduledScan${ application.id }" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div id="scheduledScanFormDiv${ application.id }">
		<%@ include file="/WEB-INF/views/applications/forms/addScheduledScanForm.jsp" %>
	</div>
</div>
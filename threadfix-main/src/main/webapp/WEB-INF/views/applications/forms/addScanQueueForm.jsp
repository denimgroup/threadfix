<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<h4 id="myModalLabel">Add Scan Task to Queue</h4>
</div>

<spring:url value="/configuration/scanqueue/organizations/{orgId}/applications/{applicationId}/addScanQueueTask" var="addScanQueueTaskUrl">
	<spring:param name="orgId" value="${ application.organization.id }" />
	<spring:param name="applicationId" value="${ application.id }" />
</spring:url>
<form id="addScanQueueTaskForm${ application.id }" method="post" action="${ fn:escapeXml(addScanQueueTaskUrl) }">
	<div class="modal-body">
		<c:if test="${ not empty scanQueueTaskError }">
			<div id="scanQueueError${ application.id }" class="alert alert-error hide-after-submit">
				<c:out value="${ scanQueueTaskError }"/>
			</div>
		</c:if>
	</div>
	<div style="margin-bottom:20px;">
	&nbsp;&nbsp;Scan Type:&nbsp;&nbsp;&nbsp;   
	<select id="scanQueueType" name="scanQueueType" >
		<c:forEach items="${scannerTypeList}" var="type">
    		<option value="${type}">${type}</option>
		</c:forEach>
	</select>
	</div>
	<div class="modal-footer">
		<button id="closeScanQueueForm${ application.id }" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<button class="modalSubmit btn btn-primary" data-success-div="scanQueueDiv${ application.id }" 
				id="addScanQueueButton${ application.id }" type="button">Submit</button>
	</div>
</form>	
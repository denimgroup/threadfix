<%@ include file="/common/taglibs.jsp"%>
<%@include file="/WEB-INF/views/applications/modals/addScanQueueModal.jsp"%>

<div id="scanQueueDiv${ application.id }">
	<table class="table">
			<thead>
				<tr>
					<th id="scanQueueTable">ID</th>
					<th>Status</th>
					<th>Scanner</th>
					<th>Created Time</th>
					<th>Start Time</th>
					<th>End Time</th>
					<c:if test="${ canManageApplications }">
						<th class="centered last"></th>
					</c:if>
				</tr>
			</thead>
			<tbody>
				<c:forEach items="${application.scanQueueTasks}" var="scanQueueTask" varStatus="status">
					<tr class="bodyRow">
						<td>
							<spring:url value="/configuration/scanqueue/{scanQueueTaskId}/detail" var="detailUrl">
								<spring:param name="scanQueueTaskId" value="${ scanQueueTask.id }" />
							</spring:url>
							<a href='<c:out value="${detailUrl}" />'><c:out value="${scanQueueTask.id}" />
							</a>
						</td> 
						<td><c:out value="${scanQueueTask.showStatusString()}" /></td>
						<td id="scannerType${ status.count }"><c:out value="${scanQueueTask.scanner}" /></td>
						<td><fmt:formatDate value="${ scanQueueTask.createTime }" type="both" dateStyle="short" timeStyle="short" /></td>
						<td><fmt:formatDate value="${ scanQueueTask.startTime }" type="both" dateStyle="short" timeStyle="short" /></td>
						<td><fmt:formatDate value="${ scanQueueTask.endTime }" type="both" dateStyle="short" timeStyle="short" /></td>	
						<c:if test="${ canManageApplications }">
							<td class="centered">
								<spring:url value="/configuration/scanqueue/organizations/{orgId}/applications/{appId}/scanQueueTask/{taskId}/delete" var="deleteUrl">
									<spring:param name="orgId" value="${ application.organization.id }"/>
									<spring:param name="appId" value="${ application.id }"/>
									<spring:param name="taskId" value="${ scanQueueTask.id }"/>
								</spring:url>
				                <a class="btn btn-danger scanQueueDelete" data-delete-form="deleteForm${ scanQueueTask.id }">Delete</a>
								<form id="deleteForm${ scanQueueTask.id }" method="POST" action="${ fn:escapeXml(deleteUrl) }"></form>				
							</td>
						</c:if>				
					</tr>
				</c:forEach>
			</tbody>
	</table>
</div>
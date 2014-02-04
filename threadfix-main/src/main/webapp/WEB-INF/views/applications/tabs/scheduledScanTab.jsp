<%@ include file="/common/taglibs.jsp"%>
<%@include file="/WEB-INF/views/applications/modals/addScheduledScanModal.jsp"%>

<div id="scanQueueDiv${ application.id }">
	<table class="table">
			<thead>
				<tr>
					<th id="scanQueueTable">ID</th>
					<th>Scanner</th>
					<th>Time</th>
					<th>Frequency</th>
					<c:if test="${ canManageApplications }">
						<th class="centered last"></th>
					</c:if>
				</tr>
			</thead>
			<tbody>
            <c:if test="${ empty application.scheduledScans }">
                <tr class="bodyRow">
                    <td colspan="5" style="text-align:center;">No Scheduled Scans found.</td>
                </tr>
            </c:if>
				<c:forEach items="${application.scheduledScans}" var="scheduledScan" varStatus="status">
					<tr class="bodyRow">
						<td><c:out value="${scheduledScan.id}" /></td>
						<td><c:out value="${scheduledScan.scanner}" /></td>
                        <td><c:out value="${scheduledScan.day}" />&nbsp;<c:out value="${scheduledScan.hour}" />:<c:out value="${scheduledScan.minute}" />
                            &nbsp;<c:out value="${scheduledScan.period}" /></td>
                        <td><c:out value="${scheduledScan.frequency}" /></td>
						<c:if test="${ canManageApplications }">
							<td class="centered">
								<spring:url value="/organizations/{orgId}/applications/{appId}/scheduledScans/scheduledScan/{scheduledScanId}/delete" var="deleteUrl">
									<spring:param name="orgId" value="${ application.organization.id }"/>
									<spring:param name="appId" value="${ application.id }"/>
									<spring:param name="scheduledScanId" value="${ scheduledScan.id }"/>
								</spring:url>
				                <a class="btn btn-danger scheduledScanDelete" data-delete-form="deleteScheduledForm${ scheduledScan.id }">Delete</a>
								<form id="deleteScheduledForm${ scheduledScan.id }" method="POST" action="${ fn:escapeXml(deleteUrl) }"></form>
							</td>
						</c:if>				
					</tr>
				</c:forEach>
			</tbody>
	</table>
</div>
<%@ include file="/common/taglibs.jsp"%>

<%@ include file="/WEB-INF/views/successMessage.jspf" %>

<c:if test="${ canManageDefectTrackers }">
	<a id="addNewDTButton" href="#createDefectTracker" role="button" class="btn" data-toggle="modal">Add New Defect Tracker</a>
</c:if>

<table class="table table-striped">
	<thead>
		<tr>
		    <th class="medium first">Name</th>
			<th class="long">URL</th>
			<th>Type</th>
			<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_DEFECT_TRACKERS">
				<th class="centered">Edit / Delete</th>
			</security:authorize>
		</tr>
	</thead>
	<tbody id="defectTrackerTableBody">
	<c:if test="${ empty defectTrackerList }">
		<tr class="bodyRow">
			<td colspan="5" style="text-align:center;">No Defect Trackers found.</td>
		</tr>
	</c:if>
	<c:forEach var="defectTracker" items="${ defectTrackerList }" varStatus="status">
		<tr class="bodyRow">
		    <td ng-non-bindable id="defectTrackerName${ status.count }">
		    	<c:out value="${ defectTracker.name }"/>
		    </td>
			<td ng-non-bindable id="defectTrackerUrl${ status.count }">
				<c:out value="${ defectTracker.url }"/>
			</td>
			<td ng-non-bindable id="defectTrackerType${ status.count }">
				<c:out value="${ defectTracker.defectTrackerType.name }"/>
			</td>
			<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_DEFECT_TRACKERS">
				<td class="centered">	
					<a id="editDefectTracker${ status.count }Button" href="#editDefectTracker${ defectTracker.id }" role="button" class="btn" data-toggle="modal">Edit / Delete</a>
					<%@ include file="/WEB-INF/views/config/defecttrackers/modals/editDTModal.jsp" %>
				</td>
			</security:authorize>
		</tr>
	</c:forEach>
	</tbody>
</table>

<c:if test="${ canManageDefectTrackers }">
	<%@ include file="/WEB-INF/views/config/defecttrackers/modals/createDTModal.jsp" %>
</c:if>

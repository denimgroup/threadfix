<%@ include file="/common/taglibs.jsp"%>

<%@ include file="/WEB-INF/views/successMessage.jspf" %>

<table class="table table-striped">
	<thead>
		<tr>
		    <th class="medium first">Name</th>
			<th class="long">URL</th>
			<th>Type</th>
			<th class="centered">Edit</th>
			<th class="centered">Delete</th>
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
		    <td id="defectTrackerName${ status.count }">
		    	<c:out value="${ defectTracker.name }"/>
		    </td>
			<td id="defectTrackerUrl${ status.count }">
				<c:out value="${ defectTracker.url }"/>
			</td>
			<td id="defectTrackerType${ status.count }">
				<c:out value="${ defectTracker.defectTrackerType.name }"/>
			</td>
			<td class="centered">	
				<a id="editDefectTracker${ status.count }Button" href="#editDefectTracker${ defectTracker.id }" role="button" class="btn" data-toggle="modal">Edit</a>
				<%@ include file="/WEB-INF/views/config/defecttrackers/modals/editDTModal.jsp" %>
			</td>
			<td class="centered">
				<spring:url value="/configuration/defecttrackers/{defectTrackerId}/delete" var="deleteUrl">
					<spring:param name="defectTrackerId" value="${ defectTracker.id }" />
				</spring:url>
				<form:form id="deleteForm${ defectTracker.id }" method="POST" action="${ fn:escapeXml(deleteUrl) }">
					<a id="deleteButton${ status.count }" class="btn btn-primary" type="submit" onclick="return deleteDefectTracker('<c:out value='${ deleteUrl }'/>');">Delete</a>
				</form:form>
			</td>
		</tr>
	</c:forEach>
	</tbody>
</table>

<c:if test="${ canManageDefectTrackers }">
	<a id="addNewDTButton" href="#createDefectTracker" role="button" class="btn" data-toggle="modal">Add New Defect Tracker</a>
	<%@ include file="/WEB-INF/views/config/defecttrackers/modals/createDTModal.jsp" %>
</c:if>

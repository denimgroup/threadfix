<%@ include file="/common/taglibs.jsp"%>

<table class="table auto table-striped">
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
			<td colspan="3" style="text-align:center;">No Defect Trackers found.</td>
		</tr>
	</c:if>
	<c:forEach var="defectTracker" items="${ defectTrackerList }">
		<tr class="bodyRow">
		    <td>
		    	<spring:url value="/configuration/defecttrackers/{defectTrackerId}" var="dtUrl">
					<spring:param name="defectTrackerId" value="${ defectTracker.id }" />
				</spring:url>
				<a href="${ fn:escapeXml(dtUrl) }">
		            <c:out value="${ defectTracker.name }"/>
		        </a> 
		    </td>
			<td>
				<c:out value="${ defectTracker.url }"/>
			</td>
			<td>
				<c:out value="${ defectTracker.defectTrackerType.name }"/>
			</td>
			<td class="centered">	
				<a id="editDefectTracker${ defectTracker.id }" href="#editDefectTracker${ defectTracker.id }" role="button" class="btn" data-toggle="modal">Edit</a>
				<%@ include file="/WEB-INF/views/config/defecttrackers/modals/editDTModal.jsp" %>
			</td>
			<td class="centered">
				<spring:url value="/configuration/defecttrackers/{defectTrackerId}/delete" var="deleteUrl">
					<spring:param name="defectTrackerId" value="${ defectTracker.id }" />
				</spring:url>
				<form:form id="deleteForm${ defectTracker.id }" method="POST" action="${ fn:escapeXml(deleteUrl) }">
					<a id="deleteButton${ defectTracker.id }" class="btn btn-primary" type="submit" onclick="return deleteDefectTracker('<c:out value='${ deleteUrl }'/>');">Delete</a>
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
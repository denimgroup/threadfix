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
				<a href="#editDefectTracker${ defectTracker.id }" role="button" class="btn" data-toggle="modal">Edit</a>
				<%@ include file="/WEB-INF/views/config/defecttrackers/modals/editDTModal.jsp" %>
			</td>
			<td class="centered">	
				<a href="#deleteDefect${ defectTracker.id }" role="button" class="btn btn-primary" data-toggle="modal">Delete</a>
			</td>
		</tr>
	</c:forEach>
	</tbody>
</table>

<c:if test="${ canManageDefectTrackers }">
	<a href="#createDefectTracker" role="button" class="btn" data-toggle="modal">Add New Defect Tracker</a>
	<%@ include file="/WEB-INF/views/config/defecttrackers/modals/createDTModal.jsp" %>
</c:if>
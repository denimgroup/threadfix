<%@ include file="/common/taglibs.jsp"%>

<div id="editDefectTracker${ defectTracker.id }" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div class="modal-header">
		<h4 id="myModalLabel">
			Edit Defect Tracker
			<span style="float:right; margin-top:-5px;">
				<spring:url value="/configuration/defecttrackers/{defectTrackerId}/delete" var="deleteUrl">
					<spring:param name="defectTrackerId" value="${ defectTracker.id }" />
				</spring:url>
				<form:form id="deleteForm${ defectTracker.id }" method="POST" action="${ fn:escapeXml(deleteUrl) }">
					<a id="deleteButton${ status.count }" class="btn btn-danger header-button" type="submit" onclick="return deleteDefectTracker('<c:out value='${ deleteUrl }'/>', 'deleteButton${ status.count }');">Delete</a>
				</form:form>
			</span>
		</h4>
	</div>
	<div id="dtFormDiv${defectTracker.id }">
		<%@ include file="/WEB-INF/views/config/defecttrackers/forms/editDTForm.jsp" %>
	</div>
</div>
<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/configuration/defecttrackers/new" var="saveUrl"/>
<form:form id="createDefectTrackerForm" style="margin-bottom:0px;" modelAttribute="defectTracker" method="post" action="${ fn:escapeXml(saveUrl) }">
	<div class="modal-body">
		<table class="dataTable">
			<tbody>
			    <tr>
					<td class="no-color">Name</td>
					<td class="inputValue">
						<form:input style="margin:5px;" id="nameInput" path="name" cssClass="focus" size="50" maxlength="50"/>
					</td>
					<td class="no-color" style="padding-left: 5px">
						<form:errors path="name" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td class="no-color">URL</td>
					<td class="no-color inputValue">
						<c:if test="${ not empty defectTracker.url }">
							<script>
								var initialUrl = '<c:out value="${ defectTracker.url }"/>';
							</script>
						</c:if>
						<form:input style="margin:5px;" id="urlInput" path="url" cssClass="focus" size="50" maxlength="255"/>
					</td>
					<td class="no-color" style="padding-left: 5px">
						<form:errors path="url" cssClass="errors" />
						<c:if test="${ showKeytoolLink }">
							<span class="errors">Instructions for importing a self-signed certificate can be found</span> <a target="_blank" href="http://code.google.com/p/threadfix/wiki/ImportingSelfSignedCertificates">here</a>.
						</c:if>
					</td>
				</tr>
				<tr>	
					<td class="no-color">Type</td>
					<td class="no-color inputValue">
						<c:if test="${ not empty defectTracker.defectTrackerType.id }">
							<script>
								var initialTrackerTypeId = '<c:out value="${ defectTracker.defectTrackerType.id }"/>';
							</script>
						</c:if>
						<form:select style="margin:5px;" id="defectTrackerTypeSelect" path="defectTrackerType.id">
							<form:options items="${ defectTrackerTypeList }" itemValue="id" itemLabel="name" />
						</form:select>
					</td>
					<td class="no-color" style="padding-left: 5px">
						<form:errors path="defectTrackerType.id" cssClass="errors" />
					</td>
				</tr>
			</tbody>
		</table>
	</div>
	<div class="modal-footer">
		<input type="hidden" name="applicationId" value="<c:out value="${ application.id }"/>">
		<button id="closeNewDTModalButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitDTCreateModal" class="btn btn-primary" onclick="javascript:createDTAndRefresh('<c:out value="${saveUrl }"/>');return false;">Create Defect Tracker</a>
	</div>
</form:form>
<script>
$("#createDefectTrackerForm").keypress(function(e){
    if (e.which == 13){
        $("#submitDTCreateModal").click();
    }
});
</script>

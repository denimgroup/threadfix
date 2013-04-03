<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/organizations/{orgId}/applications/{appId}/edit/addDTAjax" var="saveUrl">
	<spring:param name="orgId" value="${ application.organization.id }"/>
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>
<form:form id="addDTForm" style="margin-bottom:0px;" modelAttribute="application" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
	<div class="modal-body">
		<table>
			<tr>
				<td>Defect Tracker</td>
				<td class="inputValue">
					<c:if test="${ not empty defectTrackerList }">
						<form:select style="margin:5px;" id="defectTrackerId" path="defectTracker.id">
							<form:option value="0" label="<none>"/>
							<form:options items="${defectTrackerList}" itemValue="id" itemLabel="displayName"/>
						</form:select>
						<c:if test="${ canManageDefectTrackers }">
							<a style="padding-left:10px;" id="configureDefectTrackersLink" href="<spring:url value="/configuration/defecttrackers/new"/>">Create a Defect Tracker</a>
						</c:if>
					</c:if>
					<a id="createDefectTrackerButtonInModal" href="#" class="btn" onclick="switchDTModals()">Create New Defect Tracker</a>
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="defectTracker.id" cssClass="errors" />
				</td>
			</tr>
			<tr class="defecttracker_row">
				<td>Username</td>
				<td class="inputValue">
					<form:input style="margin:5px;" id="username" path="userName" size="50" maxlength="50"/>
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="userName" cssClass="errors" />
				</td>
			</tr>
			<tr class="defecttracker_row">
				<td>Password</td>
				<td class="inputValue">						
					<form:password style="margin:5px;" id="password" showPassword="true" path="password" size="50" maxlength="50" />
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="password" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td>
				<spring:url value="/organizations/{orgId}/applications/jsontest" var="testUrl">
					<spring:param name="orgId" value="${ application.organization.id }" />
					</spring:url>
				<a id="testConnectionLink" href="javascript:jsonTest('${ fn:escapeXml(testUrl) }');" id="jsonLink">Test Connection</a>
				</td>
				<td>
				<div id="toReplaceDT">
				</div>
				</td>
			</tr>
			<tr class="defecttracker_row">
				<td id="projectname">Product Name</td>
				<td class="inputValue">
					<form:select style="margin:5px;" id="projectList" path="projectName">
						<c:if test="${ not empty application.projectName }">
							<option value="${ application.projectName }"><c:out value="${ application.projectName }"/></option>
						</c:if>
					</form:select>
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="projectName" cssClass="errors" />
				</td>
			</tr>
		</table>
	</div>
	<div class="modal-footer">
		<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitDTModal" class="btn btn-primary" onclick="javascript:addDTAndRefresh('<c:out value="${saveUrl }"/>');return false;">Add Defect Tracker</a>
	</div>
</form:form>
<script>
$("#addDTForm").keypress(function(e){
    if (e.which == 13){
        $("#submitDTModal").click();
    }
});
</script>

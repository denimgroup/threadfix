<%@ include file="/common/taglibs.jsp"%>

<spring:url value="{appId}/edit" var="editUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>
<spring:url value="{appId}/delete" var="deleteUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>
	<div class="modal-header">
		<h4 id="myModalLabel">Edit Application
			<span class="delete-span">
				<a class="btn btn-danger header-button" id="deleteLink" href="${ fn:escapeXml(deleteUrl) }" 
						onclick="return confirm('Are you sure you want to delete the application?')">
					Delete
				</a>
			</span>
		</h4>
	</div>
	<spring:url value="/organizations/{orgId}/applications/{appId}/edit" var="editSaveUrl">
		<spring:param name="orgId" value="${ application.organization.id }"/>
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
	<form:form style="margin-bottom:0px;" id="editAppForm" modelAttribute="application" method="post" autocomplete="off" action="${fn:escapeXml(editSaveUrl)}">
	<div class="modal-body">
		<table>
			<tr class="left-align">
				<td style="padding:5px;">Name</td> 
				<td style="padding:5px;">
					<form:input style="margin-bottom:0px;" id="nameInput" path="name" cssClass="focus" size="50" maxlength="60" />
				  	<form:errors path="name" cssClass="errors" />
				</td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">URL</td>
				<td style="padding:5px;">
					<form:input style="margin-bottom:0px;" id="urlInput" path="url" size="50" maxlength="255" />
				  	<form:errors path="url" cssClass="errors" />
			  	</td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">Unique ID</td>
				<td style="padding:5px;">
					<form:input style="margin-bottom:0px;" id="uniqueIdInput" path="uniqueId" size="50" maxlength="255" />
				  	<form:errors path="uniqueId" cssClass="errors" />
			  	</td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">Team</td>
				<td style="padding:5px;"><c:out value="${ application.organization.name }"/></td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">Criticality</td>
				<td style="padding:5px;">
					<form:select style="margin-bottom:0px;" id="criticalityId" path="applicationCriticality.id">
						<form:options items="${applicationCriticalityList}" itemValue="id" itemLabel="name"/>
					</form:select>
					<form:errors path="applicationCriticality.id" cssClass="errors" />
				</td>
			</tr>
			<spring:url value="/organizations/{orgId}/applications/jsontest" var="testUrl">
				<spring:param name="orgId" value="${ application.organization.id }" />
			</spring:url>
			<tr class="left-align" id="appDTDiv" data-json-test-url="<c:out value="${ testUrl }"/>">
				<%@ include file="/WEB-INF/views/applications/defectTrackerRow.jsp" %>
			</tr>
			<tr class="left-align" id="appWafDiv">
				<%@ include file="/WEB-INF/views/applications/wafRow.jsp" %>
			</tr>
			
		</table>
	</div>
	<div class="modal-footer">
		<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitAppModal${ organization.id }" class="modalSubmit btn btn-primary" data-success-div="headerDiv">Save Changes</a>
	</div>
</form:form>

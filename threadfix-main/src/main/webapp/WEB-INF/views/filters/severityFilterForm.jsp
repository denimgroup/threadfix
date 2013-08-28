<%@ include file="/common/taglibs.jsp"%>

<c:choose>
	<c:when test="${ type == 'Application' }">
		<spring:url value="/organizations/{orgId}/applications/{appId}/severityFilter/set" var="editFilterUrl">
			<spring:param name="orgId" value="${severityFilter.application.organization.id}"/>
			<spring:param name="appId" value="${severityFilter.application.id}"/>
		</spring:url>
	</c:when>
	<c:when test="${ type == 'Organization' }">
		<spring:url value="/organizations/{orgId}/severityFilter/set" var="editFilterUrl">
			<spring:param name="orgId" value="${severityFilter.organization.id}"/>
		</spring:url>
	</c:when>
	<c:otherwise>
		<spring:url value="/configuration/severityFilter/set" var="editFilterUrl">
		</spring:url>
	</c:otherwise>
</c:choose>

<form:form id="severityFilterForm" 
		style="margin-bottom:0px;" 
		modelAttribute="severityFilter" 
		method="post" 
		action="${ fn:escapeXml(editFilterUrl) }">
	<div class="modal-body">
	
	<table class="table noBorders">
		<tbody>
			<tr>
				<td>Enable Severity Filters</td>
				<td>
					<form:checkbox id="enabledBox" style="width:320px" path="enabled"/>
				</td>
				<td><form:errors path="enabled" cssClass="errors" /></td>
			</tr>
			<tr>
				<td>Show Critical</td>
				<td>
					<form:checkbox 
						class="needsEnabled"
						style="width:320px"
						path="showCritical"/>
				</td>
				<td><form:errors path="showCritical" cssClass="errors" /></td>
			</tr>
			<tr>
				<td>Show High</td>
				<td>
					<form:checkbox 
						class="needsEnabled"
						style="width:320px"
						path="showHigh"/>
				</td>
				<td><form:errors path="showHigh" cssClass="errors" /></td>
			</tr>
			<tr>
				<td>Show Medium</td>
				<td>
					<form:checkbox 
						class="needsEnabled"
						style="width:320px"
						path="showMedium"/>
				</td>
				<td><form:errors path="showMedium" cssClass="errors" /></td>
			</tr>
			<tr>
				<td>Show Low</td>
				<td>
					<form:checkbox 
						class="needsEnabled"
						style="width:320px"
						path="showLow"/>
				</td>
				<td><form:errors path="showLow" cssClass="errors" /></td>
			</tr>
			<tr>
				<td>Show Info</td>
				<td>
					<form:checkbox 
						class="needsEnabled"
						style="width:320px"
						path="showInfo"/>
				</td>
				<td><form:errors path="showInfo" cssClass="errors" /></td>
			</tr>
		</tbody>
	</table>
	</div>
	<div class="modal-footer">
		<button id="closeSeverityFilterFormButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitSeverityFilterForm" 
				class="modalSubmit btn btn-primary" 
				data-success-div="tableDiv"
				data-form-div="severityFilterFormDiv"
				>
			Save Changes
		</a>
	</div>
</form:form>

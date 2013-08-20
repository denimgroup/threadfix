<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/organizations/{orgId}/applications/{appId}/filters/{filterId}/edit" var="editFilterUrl">
	<spring:param name="filterId" value="${vulnFilter.id}"/>
	<spring:param name="orgId" value="${vulnFilter.application.organization.id}"/>
	<spring:param name="appId" value="${vulnFilter.application.id}"/>
</spring:url>
<form:form id="editFilterForm${ status.count }" 
		style="margin-bottom:0px;" 
		modelAttribute="vulnerabilityFilter" 
		method="post" 
		action="${ fn:escapeXml(editFilterUrl) }">
	<div class="modal-body">
	
	<c:if test="${ not autocompleteJson }">
		<%@ include file="/WEB-INF/views/filters/buildJSON.jspf"%>
	</c:if>
	
	<table class="table noBorders">
		<tbody>
			<tr>
				<td>Source Vulnerability Type</td>
				<td>
					<form:input style="width:320px"
							class="addAutocomplete" 
							path="sourceGenericVulnerability.name" 
							data-provide="typeahead"
							data-source ="${ autocompleteJson }"
							value="${ vulnFilter.sourceGenericVulnerability.name }"/>
				</td>
				<td><form:errors path="sourceGenericVulnerability.name" cssClass="errors" /></td>
			</tr>
			<tr>
				<td>Target Severity Type</td>
				<td>
					<form:select style="width:320px"
						path="targetGenericSeverity.id" 
						items="${genericSeverities}" 
						itemLabel="name"
						itemValue="id"
						value="${ vulnFilter.targetGenericSeverity.id }"
						/>
				</td>
				<td><form:errors path="targetGenericSeverity.id" cssClass="errors" /></td>
			</tr>
		</tbody>
	</table>
	</div>
	<div class="modal-footer">
		<button id="closeNewFilterFormButton${ status.count }" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitFilterModalEdit${ status.count }" 
				class="modalSubmit btn btn-primary" 
				data-success-div="tableDiv"
				data-form-div="formDiv${ status.count }"
				>
			Save Changes
		</a>
	</div>
</form:form>

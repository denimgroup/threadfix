<%@ include file="/common/taglibs.jsp"%>

<c:choose>
	<c:when test="${ type == 'Application' }">
		<spring:url value="/organizations/{orgId}/applications/{appId}/filters/new" var="newFilterUrl">
			<spring:param name="orgId" value="${vulnerabilityFilter.application.organization.id}"/>
			<spring:param name="appId" value="${vulnerabilityFilter.application.id}"/>
		</spring:url>
	</c:when>
	<c:when test="${ type == 'Organization' }">
		<spring:url value="/organizations/{orgId}/filters/new" var="newFilterUrl">
			<spring:param name="orgId" value="${vulnerabilityFilter.organization.id}"/>
		</spring:url>
	</c:when>
	<c:otherwise>
		<spring:url value="/configuration/filters/new" var="newFilterUrl"/>
	</c:otherwise>
</c:choose>

<form:form id="newFilterForm" 
		style="margin-bottom:0px;" 
		modelAttribute="vulnerabilityFilter" 
		method="post" 
		action="${ fn:escapeXml(newFilterUrl) }">
	<div class="modal-body">
	<table class="table noBorders">
		<tbody>
			<tr>
				<td>Source Vulnerability Type</td>
				<td>
					<c:set var="autocompleteJson" value='["'/>
					<c:set var="quote" value='"'/>					
					<c:forEach items="${ genericVulnerabilities }" var="genericVulnerability">
						<c:set var="autocompleteJson" 
						value="${ autocompleteJson }${ quote }, ${ quote }${ fn:replace(genericVulnerability.name, '\\\\', '&#92;') } (CWE ${ genericVulnerability.id})"/>		
					</c:forEach>
					<c:set var="autocompleteJson" value="${ autocompleteJson }${ quote }]"/>
					
					<form:input style="width:320px"
							class="addAutocomplete" 
							path="sourceGenericVulnerability.name" 
							data-provide="typeahead"
							data-source ="${ autocompleteJson }"/>
				</td>
				<td><form:errors path="sourceGenericVulnerability.name" cssClass="errors" /></td>
			</tr>
			<tr>
				<td>Target Severity Type</td>
				<td>
					<form:select style="width:320px"
						path="targetGenericSeverity.id" 
						items="${ genericSeverities }" 
						itemLabel="name"
						itemValue="id"
						/>
				</td>
				<td><form:errors path="targetGenericSeverity.id" cssClass="errors" /></td>
			</tr>
		</tbody>
	</table>
	</div>
	<div class="modal-footer">
		<button id="closeNewFilterFormButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitFilterModalCreate" class="modalSubmit btn btn-primary" data-success-div="tableDiv">
			Add Filter
		</a>
	</div>
</form:form>

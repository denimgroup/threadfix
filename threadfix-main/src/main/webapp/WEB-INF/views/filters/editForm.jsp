<script type="text/ng-template" id="editFilterForm.html">
<c:choose>
	<c:when test="${ type == 'Application' }">
		<spring:url value="/organizations/{orgId}/applications/{appId}/filters/{filterId}/edit" var="editFilterUrl">
			<spring:param name="filterId" value="${vulnFilter.id}"/>
			<spring:param name="orgId" value="${vulnFilter.application.organization.id}"/>
			<spring:param name="appId" value="${vulnFilter.application.id}"/>
		</spring:url>
	</c:when>
	<c:when test="${ type == 'Organization' }">
		<spring:url value="/organizations/{orgId}/filters/{filterId}/edit" var="editFilterUrl">
			<spring:param name="filterId" value="${vulnFilter.id}"/>
			<spring:param name="orgId" value="${vulnFilter.organization.id}"/>
		</spring:url>
	</c:when>
	<c:otherwise>
		<spring:url value="/configuration/filters/{filterId}/edit" var="editFilterUrl">
			<spring:param name="filterId" value="${vulnFilter.id}"/>
		</spring:url>
	</c:otherwise>
</c:choose>

<div id="editFilterModalDiv{{ $index }}" class="modal hide fade wide" tabindex="-1"
     role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
    <div class="modal-header">
        <h4 id="myModalLabel">Edit Vulnerability Filter

				<span class="delete-span">
					<c:choose>
                        <c:when test="${ type == 'Application' }">
                            <spring:url value="/organizations/{orgId}/applications/{appId}/filters/{filterId}/delete" var="filterDeleteUrl">
                                <spring:param name="filterId" value="${vulnFilter.id}"/>
                                <spring:param name="orgId" value="${vulnFilter.application.organization.id}"/>
                                <spring:param name="appId" value="${vulnFilter.application.id}"/>
                            </spring:url>
                        </c:when>
                        <c:when test="${ type == 'Organization' }">
                            <spring:url value="/organizations/{orgId}/filters/{filterId}/delete" var="filterDeleteUrl">
                                <spring:param name="filterId" value="${vulnFilter.id}"/>
                                <spring:param name="orgId" value="${vulnFilter.organization.id}"/>
                            </spring:url>
                        </c:when>
                        <c:otherwise>
                            <spring:url value="/configuration/filters/{filterId}/delete" var="filterDeleteUrl">
                                <spring:param name="filterId" value="${vulnFilter.id}"/>
                            </spring:url>
                        </c:otherwise>
                    </c:choose>

					<form:form id="deleteForm${ vulnFilter.id }" method="POST" action="${ fn:escapeXml(filterDeleteUrl) }">
                        <a id="deleteButton" class="filterDeleteButton btn btn-danger header-button"
                           type="submit" data-id="<c:out value='${ vulnFilter.id }'/>">Delete</a>
                    </form:form>
				</span>
        </h4>
    </div>
    <div id="formDiv{{ $index }}">

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
					<form:select style="width:320px" id="severitySelect" path="targetGenericSeverity.id">
						<c:forEach var="severity" items="${ genericSeverities }">
							<option value="${ severity.id }"
							<c:if test="${ severity.id == vulnFilter.targetGenericSeverity.id }">
								selected=selected
							</c:if>
							<c:if test="${ severity.id == -1 and empty vulnFilter.targetGenericSeverity }">
								selected=selected
							</c:if>
							><c:out value="${ severity.name }"/></option>
						</c:forEach>
					</form:select>

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
    </div>
</div>
</script>

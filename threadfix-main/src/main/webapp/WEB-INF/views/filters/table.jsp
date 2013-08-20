<%@ include file="/common/taglibs.jsp"%>

<%@ include file="/WEB-INF/views/successMessage.jspf"%>

<%@ include file="/WEB-INF/views/filters/buildJSON.jspf"%>

<a id="createNewKeyModalButton" href="#newFilterModalDiv" role="button" class="btn" data-toggle="modal">Create New Filter</a>

<table class="table table-striped">
	<thead>
		<tr>
			<th class="medium first">Vulnerability Type (CWE)</th>
			<th class="short">Severity</th>
			<th class="short">Edit/Delete</th>
		</tr>
	</thead>
	<tbody>
		<c:if test="${ empty vulnerabilityFilterList }">
			<tr class="bodyRow">
				<td colspan="4" class="centered">No filters found.</td>
			</tr>
		</c:if>
		<c:forEach var="vulnFilter" items="${ vulnerabilityFilterList }" varStatus="status">
			<tr class="bodyRow">
				<td id="genericVulnerability${ status.count }" style="max-width:270px;">
					<c:out value="${ vulnFilter.sourceGenericVulnerability.name }"/>
				</td>
				<td style="max-width:250px;word-wrap: break-word;" id="genericSeverity${ status.count }">
					<c:out value="${ vulnFilter.targetGenericSeverity.name }"></c:out>
				</td>
				<td id="edit${ status.count}">
					<a class="btn" href="#editFilterModalDiv${ vulnFilter.id }" data-toggle="modal">Edit/Delete</a>
				</td>
			</tr>
		</c:forEach>
	</tbody>
</table>

<c:forEach var="vulnFilter" items="${ vulnerabilityFilterList }" varStatus="status">
	<div id="editFilterModalDiv${ status.count }" class="modal hide fade wide" tabindex="-1"
			role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<div class="modal-header">
			<h4 id="myModalLabel">Edit Vulnerability Filter
			
				<span class="delete-span">
					<spring:url value="/organizations/{orgId}/applications/{appId}/filters/{filterId}/edit" var="filterDeleteUrl">
						<spring:param name="filterId" value="${vulnFilter.id}"/>
						<spring:param name="orgId" value="${vulnFilter.application.organization.id}"/>
						<spring:param name="appId" value="${vulnFilter.application.id}"/>
					</spring:url>
					<form:form id="deleteForm${ vulnFilter.id }" method="POST" action="${ fn:escapeXml(filterDeleteUrl) }">
						<a id="deleteButton" class="filterDeleteButton btn btn-danger header-button" 
								type="submit" data-id="<c:out value='${ vulnFilter.id }'/>">Delete</a>
					</form:form>
				</span>
			</h4>
		</div>
		<div id="formDiv${ status.count }">
			<%@ include file="/WEB-INF/views/filters/editForm.jsp"%>
		</div>
	</div>
</c:forEach>

<div id="newFilterModalDiv" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div class="modal-header">
		<h4 id="myModalLabel">New Vulnerability Filter</h4>
	</div>
	<div id="formDiv">
		<%@ include file="/WEB-INF/views/filters/newForm.jsp" %>
	</div>
</div>

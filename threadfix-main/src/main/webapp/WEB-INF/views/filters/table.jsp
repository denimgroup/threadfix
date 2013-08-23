<%@ include file="/common/taglibs.jsp"%>

<%@ include file="/WEB-INF/views/successMessage.jspf"%>
<%@ include file="/WEB-INF/views/filters/buildJSON.jspf"%>

<table class="table table-striped">
	<thead>
		<tr>
			<th style="width:500px">Vulnerability Type (CWE)</th>
			<th style="width:50px">Severity</th>
			<th style="width:50px">Type</th>
			<th style="width:130px"></th>
		</tr>
	</thead>
	<tbody>
		<c:if test="${ empty vulnerabilityFilterList and empty teamFilterList and empty globalFilterList }">
			<tr class="bodyRow">
				<td colspan="4" class="centered">No filters found.</td>
			</tr>
		</c:if>
		<c:forEach var="vulnFilter" items="${ vulnerabilityFilterList }" varStatus="status">
			<tr class="bodyRow">
				<td id="genericVulnerability${ status.count }">
					<c:out value="${ vulnFilter.sourceGenericVulnerability.name }"/>
				</td>
				<td style="word-wrap: break-word;" id="genericSeverity${ status.count }">
					<c:if test="${ empty vulnFilter.targetGenericSeverity }">
						Ignore
					</c:if>
					<c:if test="${ not empty vulnFilter.targetGenericSeverity }">
						<c:out value="${ vulnFilter.targetGenericSeverity.name }"/>
					</c:if>
				</td>
				<td>
					<c:out value="${ type }"/>
				</td>
				<td id="edit${ status.count}">
					<a class="btn" href="#editFilterModalDiv${ status.count }" data-toggle="modal">Edit/Delete</a>
				</td>
			</tr>
		</c:forEach>
		<c:forEach var="vulnFilter" items="${ teamFilterList }" varStatus="status">
			<tr class="bodyRow">
				<td id="teamGenericVulnerability${ status.count }">
					<c:out value="${ vulnFilter.sourceGenericVulnerability.name }"/>
				</td>
				<td style="word-wrap: break-word;" id="teamGenericSeverity${ status.count }">
					<c:if test="${ empty vulnFilter.targetGenericSeverity }">
						Ignore
					</c:if>
					<c:if test="${ not empty vulnFilter.targetGenericSeverity }">
						<c:out value="${ vulnFilter.targetGenericSeverity.name }"/>
					</c:if>
				</td>
				<td>
					Team
				</td>
				<td id="edit${ status.count}">
					<spring:url value="/organizations/{orgId}/filters" var="viewTeamFilterUrl">
						<spring:param name="orgId"    value="${vulnFilter.organization.id}"/>
					</spring:url>
					<a class="btn" href="<c:out value="${ viewTeamFilterUrl }"/>">View Team Filters</a>
				</td>
			</tr>
		</c:forEach>
		
		<spring:url value="/configuration/filters" var="viewGlobalFilterUrl"/>
		<c:forEach var="vulnFilter" items="${ globalFilterList }" varStatus="status">
			<tr class="bodyRow">
				<td id="globalGenericVulnerability${ status.count }">
					<c:if test="${ empty vulnFilter.targetGenericSeverity }">
						Ignore
					</c:if>
					<c:if test="${ not empty vulnFilter.targetGenericSeverity }">
						<c:out value="${ vulnFilter.targetGenericSeverity.name }"/>
					</c:if>
				</td>
				<td style="word-wrap: break-word;" id="globalGenericSeverity${ status.count }">
					<c:out value="${ vulnFilter.targetGenericSeverity.name }"></c:out>
				</td>
				<td>Global</td>
				<td id="edit${ status.count}">
					<a class="btn" href="<c:out value="${ viewGlobalFilterUrl }"/>">View Global Filters</a>
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

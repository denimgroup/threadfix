<%@ include file="/common/taglibs.jsp"%>

<%@ include file="/WEB-INF/views/successMessage.jspf"%>

<a id="createNewKeyModalButton" href="#newFilterModalDiv" role="button" class="btn" data-toggle="modal">Create New Key</a>

<table class="table table-striped">
	<thead>
		<tr>
			<th class="medium first">Vulnerability Type (CWE)</th>
			<th class="short">Severity</th>
		</tr>
	</thead>
	<tbody>
		<c:if test="${ empty vulnerabilityFilterList }">
			<tr class="bodyRow">
				<td colspan="2" class="centered">No filters found.</td>
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
			</tr>
		</c:forEach>
	</tbody>
</table>

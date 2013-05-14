<%@ include file="/common/taglibs.jsp"%>

<%@ include file="/WEB-INF/views/successMessage.jspf"%>

<a id="createNewKeyModalButton" href="#newKeyModalDiv" role="button" class="btn" data-toggle="modal">Create New Key</a>

<table class="table table-striped">
	<thead>
		<tr>
			<th class="medium first">Key</th>
			<th class="short">Note</th>
			<th class="short centered">Edit / Delete</th>
			<c:if test="${ not empty apiKeyList }">
				<th class="short last">Restricted</th>
			</c:if>
		</tr>
	</thead>
	<tbody>
		<c:if test="${ empty apiKeyList }">
			<tr class="bodyRow">
				<td colspan="4" class="centered">No keys found.</td>
			</tr>
		</c:if>
		<c:forEach var="key" items="${ apiKeyList }" varStatus="status">
			<tr class="bodyRow">
				<td id="key${ status.count }">
					<c:out value="${ key.apiKey }"></c:out>
				</td>
				<td style="max-width:320px;word-wrap: break-word;" id="note${ status.count }">
					<c:out value="${ key.note }"></c:out>
				</td>
				<td class="centered">
					<spring:url value="/configuration/keys/{keyId}/edit" var="keyEditUrl">
						<spring:param name="keyId" value="${ key.id }" />
					</spring:url>
					<a id="editKey${ status.count }" href="#editKeyModal${ key.id }" role="button" class="btn" data-toggle="modal">Edit</a> 
					<div id="editKeyModal${ key.id }" class="modal hide fade" tabindex="-1"
						role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
						<div id="formDiv${ key.id }">
							<%@ include file="/WEB-INF/views/config/keys/editForm.jsp" %>
						</div>
					</div>
				</td>
				<td id="restricted${ status.count }">
					<c:out value="${ key.isRestrictedKey }"/>
				</td>
			</tr>
		</c:forEach>
	</tbody>
</table>

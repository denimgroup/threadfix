<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/configuration/defecttrackers/{dtId}/edit/ajax" var="editUrl">
	<spring:param name="dtId" value="${ defectTracker.id }"></spring:param>
</spring:url>
<form:form id="editDefectTrackerForm${ defectTracker.id }" modelAttribute="editDefectTracker" 
		method="post" action="${ fn:escapeXml(editUrl) }">
	<div class="modal-body">
		<table class="dataTable">
			<tbody>
			    <tr>
					<td>Name</td>
					<td class="inputValue">
						<form:input id="nameInput" path="name" cssClass="focus" 
							size="50" maxlength="50" value="${ defectTracker.name }"/>
					</td>
					<td>
						<form:errors path="name" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td>URL</td>
					<td class="inputValue">
						<form:input id="urlInput" path="url" cssClass="focus" size="50" 
							maxlength="255" value="${ defectTracker.url }"/>
					</td>
					<td>
						<form:errors path="url" cssClass="errors" />
						<c:if test="${ showKeytoolLink }">
							<span class="errors">
								Instructions for importing a self-signed certificate can be found
							</span>
							<a target="_blank" 
									href="http://code.google.com/p/threadfix/wiki/ImportingSelfSignedCertificates">
								here
							</a>.
						</c:if>
					</td>
				</tr>
				<tr>	
					<td>Type</td>
					<td class="inputValue">
						<form:select id="defectTrackerTypeSelect" path="defectTrackerType.id">
							<c:forEach var="type" items="${ defectTrackerTypeList }">
								<option value="${ type.id }"
								<c:if test="${ type.id == defectTracker.defectTrackerType.id }">
									selected=selected
								</c:if>
								><c:out value="${ type.name }"/></option>
							</c:forEach>
						</form:select>
					</td>
					<td>
						<form:errors path="defectTrackerType.id" cssClass="errors" />
					</td>
				</tr>
			</tbody>
		</table>
	</div>
	<div class="modal-footer">
		<button id="closeDTModalButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitDTModal" class="btn btn-primary" 
				onclick="javascript:updateDTAndRefresh('<c:out value="${ editUrl }"/>', '#editDefectTrackerForm${ defectTracker.id }', '#editDefectTracker${ waf.id }');return false;">
			Update Defect Tracker
		</a>
	</div>
</form:form>
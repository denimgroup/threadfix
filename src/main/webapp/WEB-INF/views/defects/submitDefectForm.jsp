<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/organizations/{orgId}/applications/{appId}/defects" var="defectUrl">
	<spring:param name="orgId" value="${ application.organization.id }"/>
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>
<form:form id="submitDefectForm" modelAttribute="defectViewModel" method="post" action="${ fn:escapeXml(defectUrl) }">
	<div class="modal-body">
	<table class="dataTable">
		<tbody>
			<tr>
				<td>Component:</td>
				<td class="inputValue">
					<form:select style="width:120px;" path="selectedComponent">
						<form:options items="${projectMetadata.components}"/>
					</form:select>
				</td>
				
				<td>Version:</td>
				<td class="inputValue">
					<form:select style="width:120px;" path="version">
						<form:options items="${projectMetadata.versions}"/>
					</form:select>
				</td>
				<td>Severity:</td>
				<td class="inputValue">
					<form:select style="width:120px;" path="severity">
						<form:options items="${projectMetadata.severities}"/>
					</form:select>
				</td>
			</tr>
			<tr>
				<td>Priority:</td>
				<td class="inputValue">
					<form:select style="width:120px;" path="priority">
						<form:options items="${projectMetadata.priorities}"/>
					</form:select>
				</td>
				<td>Status:</td>
				<td class="inputValue">
					<form:select style="width:120px;" path="status">
						<form:options items="${projectMetadata.statuses}"/>
					</form:select>
				</td>
			</tr>
			<tr>
				<td>Title:</td>
				<td colspan="5" class="inputValue">
					<form:input style="width:549px;" path="summary"/>
				</td>
			</tr>
			<tr style="margin-top:5px;">
				<td style="vertical-align:top">Description:</td>
				<td colspan="5" class="inputValue">
					<form:textarea path="preamble" style="width:549px; height:100px;"/>
				</td>
			</tr>
		</tbody>
	</table>
	</div>
	<div class="modal-footer">
		<button id="closeSubmitDefectModalButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<button onclick="javascript:submitDefect('#submitDefectForm', '#submitDefectFormDiv', '#teamTable', '#submitDefectFormModal');return false;" id="submitScanModal" class="btn btn-primary">Add Defect</button>
	</div>
</form:form>

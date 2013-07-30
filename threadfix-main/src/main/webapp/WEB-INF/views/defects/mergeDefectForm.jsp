<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/organizations/{orgId}/applications/{appId}/defects/merge" var="defectUrl">
	<spring:param name="orgId" value="${ application.organization.id }"/>
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>
<form:form id="mergeDefectForm"  modelAttribute="defectViewModel" data-has-metadata="${ empty projectMetadata ? '' : '1' }"
		 method="post" action="${ fn:escapeXml(defectUrl) }">
	<div class="modal-body">
	<table class="dataTable">
		<tbody>
			<tr class="left-align">
				<td style="padding:5px;">Select Defect: </td>
				<td style="padding:5px;">
					<form:select style="margin-bottom:0px;" id="defectId" path="id">
						<form:options items="${defectList}" itemValue="nativeId" itemLabel="nativeId"/>
					</form:select>
				</td>															
			</tr>						
		</tbody>
	</table>
	</div>
	<div class="modal-footer">
		<button id="closeMergeDefectModalButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<button onclick="javascript:submitDefect('#mergeDefectForm', '#mergeDefectFormDiv', '#teamTable', '#submitDefectFormModal');return false;" id="mergeDefectButton" class="btn btn-primary">Merge Defect</button>
	</div>
</form:form>

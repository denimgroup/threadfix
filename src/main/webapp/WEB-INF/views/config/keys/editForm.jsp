<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<h4 id="myModalLabel">Edit Key</h4>
</div>
<spring:url value="/configuration/keys/{keyId}/edit" var="saveUrl">
	<spring:param name="keyId" value="${ key.id }"/>
</spring:url>
<form:form style="margin-bottom:0px;" id="editKeyForm${ key.id }" modelAttribute="apiKey" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
	<div class="modal-body">
		<table class="dataTable noBorders">
			<tbody>
				<tr>
					<td style="padding-left:8px;">Note (optional)</td>
					<td class="inputValue">
						<form:input style="margin-bottom:0px;" path="note" cssClass="focus" size="70" maxlength="255" value="${ key.note }" />
					</td>
					<td style="padding-left:5px">
						<form:errors path="note" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td style="padding-left:8px;">Restricted?</td>
					<td class="inputValue">
						<form:checkbox style="margin-bottom:0px;" path="isRestrictedKey"/>
					</td>
					<td style="padding-left:5px">
						<form:errors path="isRestrictedKey" cssClass="errors" />
					</td>
				</tr>
			</tbody>
		</table>
	</div>
	<div class="modal-footer">
		<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitKeyModal" 
			data-id="<c:out value='${ key.id }'/>" class="submitKeyModalEdit btn btn-primary">Update Key</a>
	</div>
</form:form>

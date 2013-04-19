<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/configuration/keys/new" var="newKeyUrl"/>
<form:form id="newKeyForm" style="margin-bottom:0px;" modelAttribute="apiKey" method="post" action="${ fn:escapeXml(newKeyUrl) }">
	<div class="modal-body">
	<table class="table noBorders">
		<tbody>
			<tr>
				<td>Note (optional) </td>
				<td class="inputValue">
					<form:input path="note" cssClass="focus" size="70" maxlength="255" value="${ note }" />
				</td>
				<td style="padding-left:5px">
					<form:errors path="note" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td>Restricted?</td>
				<td class="inputValue">
					<form:checkbox path="isRestrictedKey"/>
				</td>
				<td style="padding-left:5px">
					<form:errors path="isRestrictedKey" cssClass="errors" />
				</td>
			</tr>
		</tbody>
	</table>
	</div>
	<div class="modal-footer">
		<button id="closeNewKeyFormButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitKeyModalCreate" class="btn btn-primary">Create Key</a>
	</div>
</form:form>

<%@ include file="/common/taglibs.jsp"%>

<body id="formErrors">
	<spring:url value="/configuration/keys/new" var="newKeyUrl"/>
	<form:form id="newKeyForm" style="margin-bottom:0px;" modelAttribute="apiKey" method="post" action="${ fn:escapeXml(newKeyUrl) }">
		<table class="dataTable">
			<tbody>
				<tr>
					<td class="label">Note (optional) </td>
					<td class="inputValue">
						<form:input path="note" cssClass="focus" size="70" maxlength="255" value="${ note }" />
					</td>
					<td style="padding-left:5px">
						<form:errors path="note" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td class="label">Restricted?</td>
					<td class="inputValue">
						<form:checkbox path="isRestrictedKey"/>
					</td>
					<td style="padding-left:5px">
						<form:errors path="isRestrictedKey" cssClass="errors" />
					</td>
				</tr>
			</tbody>
		</table>
		<br/>
		<div class="modal-footer">
			<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
			<a id="submitTeamModal" class="btn btn-primary" onclick="javascript:submitAjaxModal('<spring:url value="/configuration/keys/new"/>', '#newKeyForm', '#formDiv', '#tableDiv', '#newKeyModalDiv');return false;">Create Key</a>
		</div>
	</form:form>
</body>

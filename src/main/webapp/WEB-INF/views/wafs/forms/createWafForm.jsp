<%@ include file="/common/taglibs.jsp"%>
	
<div class="modal-header">
	<h4 id="myModalLabel">Create New WAF</h4>
</div>
<spring:url value="/wafs/new/ajax" var="saveUrl"/>
<form:form id="wafForm" style="margin-bottom:0px;" modelAttribute="waf" method="post" action="${ fn:escapeXml(saveUrl) }">
	<div class="modal-body">
		<table class="dataTable">
			<tbody>
			    <tr>
					<td class="">Name</td>
					<td class="inputValue no-color">
						<form:input style="margin:5px;" id="wafCreateNameInput" path="name" cssClass="focus" size="50" maxlength="50"/>
					</td>
					<td style="padding-left: 5px">
						<form:errors path="name" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td>Type</td>
					<td class="inputValue no-color">
						<form:select style="margin:5px;" id="typeSelect" path="wafType.id">
							<form:options items="${ wafTypeList }" itemValue="id" itemLabel="name" />
						</form:select>
					</td>
					<td class="no-color" style="padding-left: 5px">
						<form:errors path="wafType.id" cssClass="errors" />
					</td>
				</tr>
			</tbody>
		</table>
	</div>
	<div class="modal-footer">
		<input type="hidden" name="applicationId" value="<c:out value="${ application.id }"/>">
		<input type="hidden" name="wafsPage" value="<c:out value="${ wafList }"/>">
		<button id="closeCreateWafModalButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitWafModal" class="modalSubmit btn btn-primary" data-success-div="appWafDiv">Create WAF</a>
	</div>
</form:form>

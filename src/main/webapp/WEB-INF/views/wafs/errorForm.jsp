<%@ include file="/common/taglibs.jsp"%>
	
<body id="formErrors">
	<div class="modal-header">
		<button type="button" class="close" data-dismiss="modal"
			aria-hidden="true">X</button>
		<h4 id="myModalLabel">Create New WAF</h4>
	</div>
	<spring:url value="/wafs/new/ajax" var="saveUrl"/>
	<form:form id="wafForm" style="margin-bottom:0px;" modelAttribute="waf" method="post" action="${ fn:escapeXml(saveUrl) }">
		<div class="modal-body">
			<table class="dataTable">
				<tbody>
				    <tr>
						<td>Name</td>
						<td class="inputValue">
							<form:input style="margin:5px;" id="nameInput" path="name" cssClass="focus" size="50" maxlength="50"/>
						</td>
						<td style="padding-left: 5px">
							<form:errors path="name" cssClass="errors" />
						</td>
					</tr>
					<tr>
						<td>Type</td>
						<td class="inputValue">
							<form:select style="margin:5px;" id="typeSelect" path="wafType.id">
								<form:options items="${ wafTypeList }" itemValue="id" itemLabel="name" />
							</form:select>
						</td>
						<td style="padding-left: 5px">
							<form:errors path="wafType.id" cssClass="errors" />
						</td>
					</tr>
				</tbody>
			</table>
		</div>
		<div class="modal-footer">
			<input type="hidden" name="applicationId" value="<c:out value="${ application.id }"/>">
			<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
			<a id="submitTeamModal" class="btn btn-primary" onclick="javascript:createWafAndRefresh('<c:out value="${saveUrl }"/>');return false;">Create WAF</a>
		</div>
	</form:form>
</body>
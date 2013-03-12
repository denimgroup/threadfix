<%@ include file="/common/taglibs.jsp"%>

<body id="formErrors">
	<div class="modal-header">
		<button type="button" class="close" data-dismiss="modal"
			aria-hidden="true">X</button>
		<h4 id="myModalLabel">Add WAF</h4>
	</div>
	<spring:url value="/organizations/{orgId}/applications/{appId}/edit/wafAjax" var="saveUrl">
		<spring:param name="orgId" value="${ application.organization.id }"/>
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
		<form:form style="margin-bottom:0px;" modelAttribute="application" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
		<div class="modal-body">
			<table>
				<tr>
					<td>WAF</td>
					<td class="inputValue">
						<form:select style="margin:5px;" id="wafSelect" path="waf.id">
							<form:option value="0" label="<none>" />
							<form:options items="${ wafList }" itemValue="id" itemLabel="name"/>
						</form:select>
						<a href="#" class="btn" onclick="switchWafModals()">Create New WAF</a>
					</td>
					<td style="padding-left:5px" colspan="2" >
						<form:errors path="waf.id" cssClass="errors" />
					</td>
				</tr>
			</table>
		</div>
		<div class="modal-footer">
			<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
			<button type="submit" class="btn btn-primary">Update Application</button>
		</div>
	</form:form>
</body>
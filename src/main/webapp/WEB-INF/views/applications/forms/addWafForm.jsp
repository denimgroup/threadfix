<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<h4 id="myModalLabel">Add WAF</h4>
</div>
<spring:url value="/organizations/{orgId}/applications/{appId}/edit/wafAjax" var="saveUrl">
	<spring:param name="orgId" value="${ application.organization.id }"/>
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>
<form:form id="addWafForm" style="margin-bottom:0px;" modelAttribute="application" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
	<div class="modal-body">
		<table>
			<tr>
				<td>WAF</td>
				<td class="inputValue">
					<form:select style="margin:5px;" id="wafSelect" path="waf.id">
						<form:option value="0" label="<none>" />
						<form:options items="${ wafList }" itemValue="id" itemLabel="name"/>
					</form:select>
					<a id="addWafButtonInModal" href="#" class="btn" onclick="switchWafModals()">Create New WAF</a>
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="waf.id" cssClass="errors" />
				</td>
			</tr>
		</table>
	</div>
	<div class="modal-footer">
		<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitTeamModal" class="btn btn-primary" onclick="javascript:addWafAndRefresh('<c:out value="${saveUrl }"/>');return false;">Update Application</a>
	</div>
</form:form>
<script>
$("#addWafForm").keypress(function(e){
    if (e.which == 13){
        $("#submitTeamModal").click();
    }
});
</script>

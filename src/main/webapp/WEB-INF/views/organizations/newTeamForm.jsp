<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<h4 id="myModalLabel">New Team</h4>
</div>
<spring:url value="/organizations/modalAdd" var="saveUrl"/>
<form:form style="margin-bottom:0px;" id="organizationForm" modelAttribute="organization" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
<div class="modal-body">
	Name <form:input style="margin-bottom:0px;margin-left:5px;" id="teamNameInput" path="name" cssClass="focus clear-after-submit" size="50" maxlength="60" />
		<form:errors path="name" cssClass="errors" />
</div>
<div class="modal-footer">
	<button id="closeTeamModalButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
	<a id="submitTeamModal" class="btn btn-primary" onclick="javascript:submitAjaxModal('<c:out value="${saveUrl }"/>','#organizationForm', '#formDiv', '#teamTable', '#myTeamModal','');return false;">Add Team</a>
</div>
</form:form>
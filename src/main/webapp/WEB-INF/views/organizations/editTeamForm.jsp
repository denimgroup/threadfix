<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<h4 id="myModalLabel">Edit Team <c:out value="${ organization.name }"/></h4>
</div>
<spring:url value="/organizations/{orgId}/modalEdit" var="saveUrl">
	<spring:param name="orgId" value="${ organization.id }"/>
</spring:url>
<form:form style="margin-bottom:0px;" id="organizationForm" modelAttribute="organization" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
	<div class="modal-body">
		Name <form:input style="margin-bottom:0px;margin-left:5px;" id="teamNameInput" path="name" cssClass="focus clear-after-submit" size="50" maxlength="60" />
			<form:errors path="name" cssClass="errors" />
	</div>
	<div class="modal-footer">
		<button id="closeTeamModalButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitTeamModal" class="modalSubmit btn btn-primary" data-success-div="teamTable">Save Edit</a>
	</div>
</form:form>
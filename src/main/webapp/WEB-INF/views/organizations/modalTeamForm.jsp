<%@ include file="/common/taglibs.jsp"%>

<body id="formErrors">
	<div class="modal-header">
		<button type="button" class="close" data-dismiss="modal"
			aria-hidden="true">X</button>
		<h3 id="myModalLabel">New Team</h3>
	</div>
	<spring:url value="/organizations/modalAdd" var="saveUrl"/>
	<form:form id="organizationForm" modelAttribute="organization" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
	<div class="modal-body">
		Name: <form:input id="nameInput" path="name" cssClass="focus" size="50" maxlength="60" />
			<form:errors path="name" cssClass="errors" />
	</div>
	<div class="modal-footer">
		<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitTeamModal" class="btn btn-primary" onclick="javascript:submitTeamModal('<c:out value="${saveUrl }"/>');return false;">Add Team</a>
	</div>
	</form:form>
</body>
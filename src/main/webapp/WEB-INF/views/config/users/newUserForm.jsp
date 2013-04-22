<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<h4 id="myModalLabel">New User</h4>
</div>

<div class="modal-body">
	<spring:url value="/configuration/users/new" var="saveUrl"/>

	<%@ include file="/WEB-INF/views/errorMessage.jsp"%>
	
	<%@ include file="/WEB-INF/views/config/users/form.jsp"%>
</div>
<div class="modal-footer">
	<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
	<a id="addUserButton" class="modalSubmit btn btn-primary" data-success-div="tableDiv" 
			data-form="nameAndPasswordForm">Add User</a>
</div>
<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<h4 id="myModalLabel">New Role</h4>
</div>

<div class="modal-body">
	<spring:url value="/configuration/users/new" var="saveUrl"/>

	<%@ include file="/WEB-INF/views/errorMessage.jspf"%>
	
	<%@ include file="/WEB-INF/views/config/users/form.jsp"%>
</div>
<div class="modal-footer">
	<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
	<a id="addUserButton" class="btn btn-primary"
		onclick="javascript:submitAjaxModal('<c:out value="${ saveUrl }"/>','#nameAndPasswordForm', '#newUserModal', '#tableDiv', '#newUserModal');return false;">Add User</a>
</div>
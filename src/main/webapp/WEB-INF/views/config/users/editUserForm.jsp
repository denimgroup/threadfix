<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<h4 id="myModalLabel">Edit User <c:out value="${ user.name }"/></h4>
</div>

<div class="modal-body">
	<spring:url value="/configuration/users/{userId}/edit" var="saveUrl">
		<spring:param name="userId" value="${ user.id }"/>
	</spring:url>

	<%@ include file="/WEB-INF/views/errorMessage.jsp"%>
	
	<%@ include file="/WEB-INF/views/config/users/form.jsp"%>
</div>
<div class="modal-footer">
	<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
	<a id="addUserButton" class="btn btn-primary"
		onclick="javascript:submitAjaxModal('<c:out value="${ saveUrl }"/>','#nameAndPasswordForm${ user.id }', '#editUserModal${ user.id }', '#tableDiv', '#editUserModal');return false;">Save Changes</a>
</div>
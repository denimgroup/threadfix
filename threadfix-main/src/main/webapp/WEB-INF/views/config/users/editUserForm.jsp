<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/configuration/users/{userId}/delete" var="deleteUrl">
	<spring:param name="userId" value="${ user.id }"/>
</spring:url>
<form id="command" method="POST" action="${ fn:escapeXml(deleteUrl) }">
	<div class="modal-header">
		<h4 id="myModalLabel">
			Edit User <c:out value="${ user.name }"/>
			<span class="delete-span">
                <input class="btn btn-danger" id="delete{{ user.name }}" type="submit" value="Delete" ng-click="clickedDeleteButton()"/>
			</span>
		</h4>
	</div>
</form>

<div class="modal-body">
	<spring:url value="/configuration/users/{userId}/edit" var="saveUrl">
		<spring:param name="userId" value="${ user.id }"/>
	</spring:url>

	<%@ include file="/WEB-INF/views/errorMessage.jsp"%>

	<%@ include file="/WEB-INF/views/config/users/form.jsp"%>
</div>
<div class="modal-footer">
	<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
    <button id="addUserButton<c:out value="${ user.name }"/>" class="modalSubmit btn btn-primary btn-lg" data-success-div="tableDiv"
       data-form="nameAndPasswordForm${ user.id }" disabled="disabled"
       data-form-div="editUserModal${ user.id }">Save Changes</button>
</div>
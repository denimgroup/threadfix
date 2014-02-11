<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/configuration/users/{userId}/delete" var="deleteUrl">
	<spring:param name="userId" value="${ user.id }"/>
</spring:url>
<form id="command" method="POST" action="${ fn:escapeXml(deleteUrl) }">
	<div class="modal-header">
		<h4 id="myModalLabel">
			Edit User <c:out value="${ user.name }"/>
			<span class="delete-span">
				<c:choose>
					<c:when test="${ not user.isDeletable }">
						<input class="btn btn-danger" id="delete${ status.count }" type="submit" value="Delete" onclick="javascript:alert('You cannot delete this account because doing so would leave the system without users with the ability to manage either users or roles.'); return false;"/>
					</c:when>
					<c:when test="${ user.isThisUser }">
						<input class="btn btn-danger" id="delete${ status.count }" type="submit" value="Delete" onclick="return confirm('This is your account. Are you sure you want to remove yourself from the system?')"/>
					</c:when>
					<c:otherwise>
						<input class="btn btn-danger" id="delete${ status.count }" type="submit" value="Delete" onclick="return confirm('Are you sure you want to delete this User?')"/>
					</c:otherwise>
				</c:choose>
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
    <button id="addUserButton${ user.id }" class="modalSubmit btn btn-primary btn-lg" data-success-div="tableDiv"
       data-form="nameAndPasswordForm${ user.id }" disabled="disabled"
       data-form-div="editUserModal${ user.id }">Save Changes</button>
</div>
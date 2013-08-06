<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<h4 id="myModalLabel">Permissible Users</h4>
</div>

<div class="modal-body">
	<table class="table table-striped">
		<thead>
			<tr>
				<th class="medium first">User</th>
				<th class="short"></th>
			</tr>
		</thead>
		<tbody id="userTableBody">
		<c:forEach var="user" items="${ users }" varStatus="status">
			<tr class="bodyRow">
				<td id="name${ status.count }">
					<c:out value="${ user.name }"/>
				</td>
				<td id="name${ status.count }">
					<spring:url value="/configuration/users/{userId}/permissions" var="editPermissionsUrl">
						<spring:param name="userId" value="${ user.id }"/>
					</spring:url>
					<a id="editPermissions${ status.count }" style="font-size:12px;float:right;" href="${ fn:escapeXml(editPermissionsUrl) }">Edit Permissions</a>
				</td>
			</tr>
		</c:forEach>
		</tbody>
	</table>
</div>
<div class="modal-footer">
		<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
</div>
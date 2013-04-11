<%@ include file="/common/taglibs.jsp"%>

<table class="table table-striped">
	<thead>
		<tr>
			<th class="medium first">Name</th>
			<th class="short">Edit</th>
			<th class="short">Delete</th>
		</tr>
	</thead>
	<tbody>
		<c:if test="${ empty roleList }">
			<tr class="bodyRow">
				<td colspan="6" style="text-align:center;">No roles found.</td>
			</tr>
		</c:if>
		<c:forEach var="editRole" items="${ roleList }" varStatus="status">
			<tr class="bodyRow roleRow">
				<td id="role${ status.count }">
					<c:out value="${ editRole.displayName }"/>
				</td>
				<td>
					<a id="editModalLink${ status.count }" href="#editRoleModal${ status.count }" role="button" class="btn" data-toggle="modal">Edit</a>
					<div id="editRoleModal${ status.count }" class="modal hide fade" tabindex="-1"
							role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
						<%@ include file="/WEB-INF/views/config/roles/form.jsp" %>
					</div>
				</td>
				<td>
					<spring:url value="/configuration/roles/{roleId}/delete" var="roleDeleteUrl">
						<spring:param name="roleId" value="${ editRole.id }" />
					</spring:url>
					<form:form method="POST" action="${ fn:escapeXml(roleDeleteUrl) }">
					<button class="btn btn-primary" type="submit" id="delete${ status.count }"
						
						<c:if test="${ editRole.canDelete }">
						onclick="return confirm('Are you sure you want to delete this Role? All users will have their privileges revoked.')" 
						</c:if>
						
						<c:if test="${ not editRole.canDelete }">
						onclick="alert('This role cannot be deleted because it is the last role with permissions to manage either groups, users, or roles.'); return false;" 
						</c:if>
						
						>Delete</button>
					</form:form>
				</td>
			</tr>
		</c:forEach>
	</tbody>
</table>
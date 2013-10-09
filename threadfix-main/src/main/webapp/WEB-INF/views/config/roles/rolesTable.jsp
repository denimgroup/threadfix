<%@ include file="/common/taglibs.jsp"%>

<div style="margin-top:5px;"></div>

<%@ include file="/WEB-INF/views/successMessage.jspf" %>
<%@ include file="/WEB-INF/views/errorMessage.jsp" %>

<table class="table table-striped">
	<thead>
		<tr>
			<th class="medium first">Name</th>
			<th class="short">Edit / Delete</th>
		</tr>
	</thead>
	<tbody>
		<c:if test="${ empty roleList }">
			<tr>
				<td colspan="6" style="text-align:center;">No roles found.</td>
			</tr>
		</c:if>
		<c:forEach var="editRole" items="${ roleList }" varStatus="status">
			<tr class=" roleRow">
				<td id="role${ status.count }">
					<c:out value="${ editRole.displayName }"/>
				</td>
				<td>
					<a id="editModalLink${ status.count }" 
							href="#editRoleModal${ status.count }" 
							role="button" 
							class="btn" 
							data-toggle="modal">
						Edit / Delete
					</a>
					<div id="editRoleModal${ status.count }" class="modal hide fade" tabindex="-1"
							role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
						<%@ include file="/WEB-INF/views/config/roles/form.jsp" %>
					</div>
				</td>
			</tr>
		</c:forEach>
	</tbody>
</table>
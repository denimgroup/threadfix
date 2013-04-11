<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Manage Users</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/user_page.js"></script>
</head>

<body id="config">

	<c:if test="${ not user['new'] }">

	<spring:url value="/configuration/users/{userId}/access/new" var="newUrl">
		<spring:param name="userId" value="${ user.id }"/>
	</spring:url>
	
	<h2>Edit User <c:out value="${ user.name }"/> Permissions</h2>
	
	<a id="addPermissionButton" style="text-decoration:none;" role="button" 
			class="btn" href="javascript:showAddModal()">
		Add Permissions
	</a>
	
	<div id="permsTableDiv">
		<%@ include file="/WEB-INF/views/config/users/permTable.jsp" %>
	</div>
	
	<spring:url value="/configuration/users/{userId}/access/new" var="newUrl">
		<spring:param name="userId" value="${ user.id }"/>
	</spring:url>
	<form:form id="newAccessControlMapForm" modelAttribute="accessControlMapModel" action="${ fn:escapeXml(newUrl) }">
	<script>
	$(document).ready(function(){ 
		$("#orgSelect").change(function() {
			var options = '';
			
			<c:forEach var="organization" items="${teams}">
			    if("${organization.id}" == $("#orgSelect").val()) {
					<c:forEach varStatus="status" var="application" items="${ organization.activeApplications }">
					options += 
						'<tr><td>'+
						'<input id="applicationIds${ status.count }" type="checkbox" value="${ application.id }" name="applicationIds">' +
						'<input type="hidden" value="on" name="_applicationIds"></td>' +
						'<td id="applicationName${ status.count }"><c:out value="${ application.name }"/></td>' +
						'<td>' + 
						'<select id="roleSelect${ status.count }" name="roleIdMapList">' +
						'	<option value="0">Select a Role</option>';
						<c:forEach var="role" items="${roleList}">
						options +=
							'	<option value="${application.id}-${role.id}" >${role.displayName}</option>';
						</c:forEach>
					options +=
						'</select>' + 
						'</td></tr>';
					</c:forEach>
			    }
			</c:forEach>
			
			if (options !== '') {
				$("#appSelect").html('');
				$("#appSelect").append('<thead><tr><th>Enabled</th><th>App Name</th><th>Role</th></tr></thead><tbody>');
				$("#appSelect").css("display","");
				$("#appSelect").append(options);
				$("#appSelect").append("</tbody>");
				toggleAppSelect('');
			} else {
				$("#appSelect").css("display","none");
			};
		});
	});
	</script>
		
	<!-- Modal -->
	<div id="myModal" class="modal hide fade" tabindex="-1" role="dialog"
		aria-labelledby="myModalLabel" aria-hidden="true">
		<div class="modal-header">
			<button type="button" class="close" data-dismiss="modal"
				aria-hidden="true">x</button>
			<h4 id="myModalLabel">Add Permissions Mapping</h4>
		</div>
		<div class="modal-body">
		
			<table class="bordered padded">
				<tr>
					<td>Team</td>
					<td>
						<form:select id="orgSelect" path="teamId">
							<form:option value="0" label="Select a team" />
							<form:options items="${ teams }" itemValue="id" itemLabel="name" />
						</form:select>
					</td>
				</tr>
				<tr>
					<td>All apps?</td>
					<td>
						<form:checkbox onclick="toggleAppSelect('')" id="allAppsCheckbox" checked="checked" path="allApps" />
					</td>
				</tr>
				<tr>
					<td>Team Role</td>
					<td>
						<form:select id="roleSelectTeam" path="roleId">
							<form:option value="0" label="Select a role" />
							<form:options items="${ roleList }" itemValue="id" itemLabel="displayName" />
						</form:select>
					</td>
				</tr>
			</table>
			
			<table id="appSelect" class="bordered padded bold-headers">
				
			</table>

		</div>
		<div class="modal-footer">
			<button class="btn" data-dismiss="modal" aria-hidden="true">Cancel</button>
			<button id="submitModalAdd" class="btn btn-primary" onclick="javascript:submitModal('<c:out value="${newUrl}"/>');return false;">Add Mapping</button>
			<button id="submitModalEdit" class="btn btn-primary" onclick="javascript:submitEditModal();return false;">Save Edit</button>
		</div>
	</div>
	</form:form>
	
</c:if>

</body>
	
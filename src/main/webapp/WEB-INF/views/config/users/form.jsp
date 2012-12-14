<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:if test="${ user['new'] }">New </c:if>User</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/bootstrap.min.js" media="screen"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/user_page.js"></script>
	<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/modal.css"/>
</head>

<body id="config">
	<h2><c:if test="${ user['new'] }">New </c:if>User</h2>

	<spring:url value="" var="emptyUrl"></spring:url>
	<form:form id="nameAndPasswordForm" modelAttribute="user" name="formEditUser" action="${ fn:escapeXml(emptyUrl) }">
		<table class="dataTable">
			<tr>
				<td class="label-2">Name:</td>
				<td class="inputValue-2">
					<form:input id="nameInput" path="name" cssClass="focus" size="30" maxlength="25" />
				</td>
				<td style="padding-left: 5px">
					<form:errors path="name" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td class="label-2">Password:</td>
				<td class="inputValue-2">
					<form:password id="passwordInput" path="unencryptedPassword" />
				</td>
				<td style="padding-left: 5px">
					<form:errors path="password" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td class="label-2">Confirm:</td>
				<td class="inputValue-2">
					<form:password id="passwordConfirmInput" path="passwordConfirm" />
				</td>
			</tr>
			<tr>
				<td class="label-2">LDAP user:</td>
				<td class="inputValue-2" style="text-align: left;">
					<form:checkbox onclick="togglePassword()" id="isLdapUserCheckbox" path="isLdapUser" />
				</td>
			</tr>
			<tr>
				<td class="label-2">Global Access:</td>
				<td class="inputValue-2" style="text-align: left;">
					<form:checkbox onclick="toggleRoles()" id="hasGlobalGroupAccessCheckbox" path="hasGlobalGroupAccess" />
				</td>
			</tr>
			<tr>
				<td class="label-2">Role for Global Access:</td>
				<td class="inputValue-2" style="text-align: left;">
					<form:select id="roleSelect" path="globalRole.id">
						<form:option value="0" label="Read Access" />
						<form:options items="${ roleList }" itemValue="id" itemLabel="displayName" />
					</form:select>
					
					<c:if test="${ not user.hasGlobalGroupAccess }">
						<script>$("#roleSelect").attr("disabled","disabled");</script>
					</c:if>
				</td>
				<td style="border: 0px solid black; background-color: white; padding-left: 5px">
					<form:errors id="hasGlobalGroupAccessErrors" path="hasGlobalGroupAccess" cssClass="errors" />
				</td>
			</tr>
		</table>
	
	<div style="padding-top:8px">
	<c:choose>
		<c:when test="${ user['new'] }">	
			<input id="addUserButton" type="submit" value="Add User" />
			<span style="padding-left: 10px">
				<a id="cancelLink" href="<spring:url value="/configuration/users" />">Back to Users Index</a>
			</span>
		</c:when>
		<c:otherwise>
			<input id="updateUserButton" type="submit" value="Update User" />
			<span style="padding-left: 10px">
				<spring:url value="/configuration/users" var="userUrl">
					<spring:param name="userId" value="${ user.id }"/>
				</spring:url>
				<a id="cancelLink" href="${ fn:escapeXml(userUrl) }">Back to Users Index</a>
			</span>
		</c:otherwise>
	</c:choose>
	</div>
	
	</form:form>
		
	<br>
	
	<spring:url value="/configuration/users/{userId}/access/new" var="newUrl">
		<spring:param name="userId" value="${ user.id }"/>
	</spring:url>
	
	<spring:url value="/edit" var="editUrl"/>
	
	<c:if test="${ not user['new'] }">
	
	<h2>Permissions</h2>
	
	<div id="permsTableDiv">
		
		<script>
		function showEditModal(id) {
			var options = '';
			lastId = id;
			$("#myModalLabel").html("Edit Permissions Mapping");
			$("#submitModalAdd").css("display","none");
			$("#submitModalEdit").removeAttr("style")
			$("#myModal").modal('show');
			<c:forEach var="teamMap" items="${ maps }">
				<c:if test="${ teamMap.active }">
				if (id == <c:out value="${teamMap.id}"/>) {
					$("#orgSelect").val("<c:out value='${ teamMap.organization.id }'/>");
					$("#roleSelectTeam").val("<c:out value='${ teamMap.role.id }'/>");
					$("#orgSelect").change();
					
					if (<c:out value='${teamMap.allApps}'/> ? !$("#allAppsCheckbox").is(":checked") : $("#allAppsCheckbox").is(":checked")) {
						$("#allAppsCheckbox").click();
						toggleAppSelect();
					}
					
					<c:forEach var="appMap" items="${ teamMap.accessControlApplicationMaps }">
						<c:if test="${ appMap.active }">
							$('[name="applicationIds"][value="<c:out value='${ appMap.application.id }'/>"]').click();
							$('[name="roleIdMapList"]>option[value="<c:out value='${ appMap.application.id }'/>-<c:out value='${ appMap.role.id }'/>"]').parent().val("<c:out value='${ appMap.application.id }'/>-<c:out value='${ appMap.role.id }'/>");
						</c:if>
					</c:forEach>
				}
				</c:if>
			</c:forEach>
		}
		
		function submitEditModal() {
			editUrl = '<c:out value="${editUrl}"/>'.replace("/threadfix","");
			completeEditUrl = '/threadfix/configuration/users/<c:out value="${user.id}"/>/access/' + lastId + editUrl;
			submitModal(completeEditUrl);
		}
		
		function showAddModal() {
			$("#myModalLabel").html("Add Permissions Mapping");
			$("#submitModalEdit").css("display","none");
			$("#submitModalAdd").removeAttr("style");
			$("#myModal").modal('show');
			
			$("#orgSelect").val("0");
			$("#roleSelectTeam").val("0");
			$("#orgSelect").change();
			
			if (!$("#allAppsCheckbox").is(":checked")) {
				$("#allAppsCheckbox").click();
				toggleAppSelect();
			}
		}
		
		togglePassword();
		</script>
	
		<table class="filteredTable">
			<thead>
				<tr style="background-color:#43678B;color:#FFFFFF">
					<th class="medium first">Team</th>
					<th class="medium">Application</th>
					<th class="medium">Role</th>
					<th class="short">Edit</th>
					<th class="short last">Delete</th>
					<td style="background-color:#FFFFFF;padding-left:10px"><a style="text-decoration:none;" role="button" class="btn" href="javascript:showAddModal()">Add</a></td>
				</tr>
			</thead>
			<tbody>
				<c:if test="${ empty maps }">
					<tr class="bodyRow">
						<td colspan="5" style="text-align:center;">
							<a href="javascript:showAddModal()">Add Permissions</a>
						</td>
					</tr>
				</c:if>
			
				<c:forEach var="map" items="${ maps }">
					<c:if test="${ map.allApps and map.active}">
						<tr class="bodyRow">
							<td><c:out value="${ map.organization.name }"/></td>
							<td>All</td>
							<td><c:out value="${ map.role.displayName }"/></td>
							<td style="text-align:center">
								<input id="editAppMap${ status.count }" type="submit" onclick="javascript:showEditModal(<c:out value="${ map.id }"/>)" value="Edit" />
							</td>
							<td style="text-align:center">
								<spring:url value="/configuration/users/{userId}/access/team/{mapId}/delete" var="deleteUrl">
									<spring:param name="userId" value="${ user.id }"/>
									<spring:param name="mapId" value="${ map.id }"/>
								</spring:url>
								<input id="deleteAppMap${ status.count }" type="submit" value="Delete" onclick="javascript:submitFormAndReload('${ fn:escapeXml(deleteUrl) }');return false;"/>
							</td>
						</tr>
					</c:if>
					<c:if test="${ not map.allApps }">
						<c:forEach varStatus="status" var="appMap" items="${ map.accessControlApplicationMaps }">
							<c:if test="${ appMap.active }">
								<tr class="bodyRow">
									<td><c:out value="${ map.organization.name }"/></td>
									<td><c:out value="${ appMap.application.name }"/></td>
									<td><c:out value="${ appMap.role.displayName }"/></td>
									<td style="text-align:center">
										<input id="editAppMap${ status.count }" type="submit" onclick="javascript:showEditModal(<c:out value="${ map.id }"/>)" value="Edit" />
									</td>
									<td style="text-align:center">
										<spring:url value="/configuration/users/{userId}/access/app/{mapId}/delete" var="deleteUrl">
											<spring:param name="userId" value="${ user.id }"/>
											<spring:param name="mapId" value="${ appMap.id }"/>
										</spring:url>
										<input id="deleteAppMap${ status.count }" type="submit" onclick="javascript:submitFormAndReload('${ fn:escapeXml(deleteUrl) }');return false;" value="Delete" />
									</td>
								</tr>
							</c:if>
						</c:forEach>
					</c:if>
				</c:forEach>
			</tbody>
		</table>
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
						'<td><c:out value="${ application.name }"/></td>' +
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
				toggleAppSelect();
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
			<h3 id="myModalLabel">Add Permissions mapping</h3>
		</div>
		<div class="modal-body">
		
			<table class="bordered">
				<tr>
					<th>Team</th>
					<th>All Apps</th>
					<th>Role</th>
				</tr>
				<tr>
			<td>
			<form:select id="orgSelect" path="teamId">
				<form:option value="0" label="Select a team" />
				<form:options items="${ teams }" itemValue="id" itemLabel="name" />
			</form:select>
			</td><td>
			<form:checkbox onclick="toggleAppSelect()" id="allAppsCheckbox" checked="checked" path="allApps" />
			</td><td>
			<form:select id="roleSelectTeam" path="roleId">
				<form:option value="0" label="Select a role" />
				<form:options items="${ roleList }" itemValue="id" itemLabel="displayName" />
			</form:select></td>
				</tr>
			</table>
			
			<table id="appSelect" class="bordered">
				
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

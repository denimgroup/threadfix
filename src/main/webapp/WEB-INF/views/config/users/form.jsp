<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:if test="${ user['new'] }">New </c:if>User</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/bootstrap.min.js" media="screen"></script>
	<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/bootstrap.min.css"/>
	<script>
		function confirmRoles() {
			return $("#roleSelect").children("option").filter(":selected").text() !== "User" || 
				confirm("You are switching roles from Administrator to User and will be logged out after this change.");
		}
		
		function toggleRoles() {
			if (! $("#hasGlobalGroupAccessCheckbox").is(':checked')){
				$("#roleSelect").attr("disabled","disabled");
			} else {
				$("#roleSelect").removeAttr("disabled","");
			}
		}

	</script>
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
				<td class="label-2">Global Group:</td>
				<td class="inputValue-2" style="text-align: left;">
					<form:checkbox onclick="toggleRoles()" id="hasGlobalGroupAccessCheckbox" path="hasGlobalGroupAccess" />
					
					<form:select id="roleSelect" path="globalRole.id">
						<form:option value="0" label="Select a role" />
						<form:options items="${ roleList }" itemValue="id" itemLabel="displayName" />
					</form:select>
					
					<c:if test="${ not user.hasGlobalGroupAccess }">
						<script>$("#roleSelect").css("display","none");</script>
					</c:if>
					
				</td>
				<td style="border: 0px solid black; background-color: white; padding-left: 5px">
					<form:errors id="hasGlobalGroupAccessErrors" path="hasGlobalGroupAccess" cssClass="errors" />
				</td>
			</tr>
		</table>
		<br/>
	</form:form>
	
	<c:if test="${ not user['new'] }">
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
			}
			
			
		});
	});
	
	function toggleAppSelect() {
		if ($("#allAppsCheckbox").is(':checked')){
			$("#appSelect :input").attr("disabled","disabled");
			$("#roleSelectTeam").removeAttr("disabled","");
		} else {
			$("#appSelect :input").removeAttr("disabled","");
			$("#roleSelectTeam").attr("disabled","disabled");
		}
	}
	
	function submitModal() {
		$.ajax({
			type : "POST",
			url : '<c:out value="${newUrl}"/>',
			data : $("#newAccessControlMapForm").serializeArray(),
			contentType : "application/x-www-form-urlencoded",
			dataType : "text",
			success : function(text) {
				try {
					var json = JSON.parse(text);
					alert(json.error);
				} catch (e) {
					$('#myModal').on('hidden', function () {
						$("#permsTableDiv").html(text);
				    });
				    $("#myModal").modal('hide');
				    setTimeout(function() {
						$("#orgSelect").val('');
						$("#roleSelectTeam").val('');
						$("#orgSelect").change();
						if (! $("#allAppsCheckbox").is(':checked')) {
							$("#allAppsCheckbox").click();
						}
						toggleAppSelect();
					}, 1000);
				}
			},
			error : function (xhr, ajaxOptions, thrownError){
				alert("AJAX failed.");
		    }
		});

	}
	
	function submitFormAndReload(address) {
		$.ajax({
			type : "POST",
			url : address,
			data : "",
			contentType : "application/x-www-form-urlencoded",
			dataType : "text",
			success : function(text) {
				$("#permsTableDiv").html(text);
			},
			error : function (xhr, ajaxOptions, thrownError){
				alert("AJAX failed.");
		    }
		});
	}
	</script>
		
	<!-- Button to trigger modal -->
	<a href="#myModal" role="button" class="btn" data-toggle="modal">Add</a>

	<!-- Modal -->
	<div id="myModal" class="modal hide fade" tabindex="-1" role="dialog"
		aria-labelledby="myModalLabel" aria-hidden="true">
		<div class="modal-header">
			<button type="button" class="close" data-dismiss="modal"
				aria-hidden="true">x</button>
			<h3 id="myModalLabel">Add Permissions mapping</h3>
		</div>
		<div class="modal-body">
		
			<table>
				<tr>
					<th>Team</th>
					<th>All Apps</th>
					<th>Role</th>
				</tr>
				<tr>
			<td>
			<form:select id="orgSelect" path="teamId">
				<form:option value="0" label="Select a role" />
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
			
			<table id="appSelect">
				
			</table>

		</div>
		<div class="modal-footer">
			<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
			<button class="btn btn-primary" onclick="javascript:submitModal();return false;">Add Mapping</button>
		</div>
	</div>
	</form:form>
	
	<div id="permsTableDiv">
		<table class="filteredTable">
			<thead>
				<tr style="background-color:#43678B;color:#FFFFFF">
					<th class="medium first">Team</th>
					<th class="medium">Application</th>
					<th class="medium">Role</th>
					<th class="medium last">Delete</th>
				</tr>
			</thead>
			<tbody>
				<c:if test="${ empty maps }">
					<tr class="bodyRow">
						<td colspan="4" style="text-align:center;">
							<a href="#myModal" role="button" data-toggle="modal">Add Permissions</a>
						</td>
					</tr>
				</c:if>
			
				<c:forEach var="map" items="${ maps }">
					<c:if test="${ map.allApps and map.active}">
						<tr class="bodyRow">
							<td><c:out value="${ map.organization.name }"/></td>
							<td>All</td>
							<td><c:out value="${ map.role.displayName }"/></td>
							<td>
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
									<td>
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
	</c:if>
		
	<div style="padding-top:8px">
	<c:choose>
		<c:when test="${ user['new'] }">	
			<input id="addUserButton" type="submit" onclick="javascript:$('#nameAndPasswordForm').submit()" value="Add User" />
			<span style="padding-left: 10px">
				<a id="cancelLink" href="<spring:url value="/configuration/users" />">Back to Users Index</a>
			</span>
		</c:when>
		<c:otherwise>
			<input id="updateUserButton" type="submit" onclick="javascript:$('#nameAndPasswordForm').submit()" value="Update User" />
			<span style="padding-left: 10px">
				<spring:url value="/configuration/users" var="userUrl">
					<spring:param name="userId" value="${ user.id }"/>
				</spring:url>
				<a id="cancelLink" href="${ fn:escapeXml(userUrl) }">Back to Users Index</a>
			</span>
		</c:otherwise>
	</c:choose>
	</div>
		
	
</body>

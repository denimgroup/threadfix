<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Role <c:out value="${ role.displayName }"/></title>
</head>

<body>
	<h2><c:if test="${ role['new'] }">New </c:if>Role</h2>
	
	<spring:url value="" var="emptyUrl"></spring:url>	
	<form:form modelAttribute="role" method="post" action="${fn:escapeXml(emptyUrl) }">
		<table class="dataTable">
			<tbody>
				<tr>
					<td class="label">Name:</td>
					<td class="inputValue">
						<form:input path="displayName" size="70" maxlength="255" value="${ displayName }" />
					</td>
					<td style="padding-left:5px">
						<form:errors path="displayName" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td class="label">Code:</td>
					<td class="inputValue">
						<form:input path="name" cssClass="focus" size="70" maxlength="255" value="${ name }" />
					</td>
					<td colspan="2" style="padding-left:5px">
						<form:errors path="name" cssClass="errors" />
					</td>
				</tr>
			</tbody>
		</table>
		<h3>Permissions</h3>
		
		<table class="formattedTable" style="margin-top:5px">
			<thead>
				<tr>
					<th class="long first">Permission</th>
					<th class="short" style="text-align: center;">Yes</th>
					<th class="short last">No</th>
				</tr>
			</thead>
			<tbody>
				<tr class="bodyRow">
					<td>Generate Reports</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canGenerateReports" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canGenerateReports" value="true" /></td>
				</tr>
				<tr class="bodyRow">
					<td>Generate Waf Rules</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canGenerateWafRules" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canGenerateWafRules" value="true" /></td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Api Keys</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageApiKeys" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageApiKeys" value="true" /></td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Applications</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageApplications" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageApplications" value="true" /></td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Groups</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageGroups" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageGroups" value="true" /></td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Remote Providers</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageRemoteProviders" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageRemoteProviders" value="true" /></td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Roles</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageRoles" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageRoles" value="true" /></td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Teams</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageTeams" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageTeams" value="true" /></td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Users</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageUsers" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageUsers" value="true" /></td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Wafs</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageWafs" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canManageWafs" value="true" /></td>
				</tr>
				<tr class="bodyRow">
					<td>Modify Vulnerabilities</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canModifyVulnerabilities" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canModifyVulnerabilities" value="true" /></td>
				</tr>
				<tr class="bodyRow">
					<td>Submit Defects</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canSubmitDefects" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canSubmitDefects" value="true" /></td>
				</tr>
				<tr class="bodyRow">
					<td>Upload Scans</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canUploadScans" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canUploadScans" value="true" /></td>
				</tr>
				<tr class="bodyRow">
					<td>View Error Logs</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canViewErrorLogs" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canViewErrorLogs" value="true" /></td>
				</tr>
				<tr class="bodyRow">
					<td>View Job Statuses</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canViewJobStatuses" value="false" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							path="canViewJobStatuses" value="true" /></td>
				</tr>
			</tbody>
		</table>
		<br/>
		<c:if test="${ role['new'] }">
			<input id="createRoleButton" type="submit" value="Create Role" />
		</c:if>
		<c:if test="${ not role['new'] }">
			<input id="updateRoleButton" type="submit" value="Update Role" />
		</c:if>
		<span style="padding-left: 10px">
			<a id="backToRolesButton" href="<spring:url value="/configuration/roles"/>">Back to Roles</a>
		</span>
	</form:form>
</body>
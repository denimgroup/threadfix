<%@ include file="/common/taglibs.jsp"%>

<head>
<title>Role <c:out value="${ role.displayName }" /></title>
</head>

<body>
	<h2>
		<c:if test="${ role['new'] }">New </c:if>
		Role
	</h2>

	<spring:url value="" var="emptyUrl"></spring:url>
	<form:form modelAttribute="role" method="post"
		action="${fn:escapeXml(emptyUrl) }">
		<table class="dataTable">
			<tbody>
				<tr>
					<td class="label">Name:</td>
					<td class="inputValue"><form:input path="displayName"
							size="70" maxlength="255" value="${ displayName }" /></td>
					<td style="padding-left: 5px"><form:errors path="displayName"
							cssClass="errors" /></td>
				</tr>
			</tbody>
		</table>
		<h3>Permissions</h3>

		<table class="formattedTable" style="margin-top: 5px">
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
							id="canGenerateReportsTrue" path="canGenerateReports"
							value="true" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canGenerateReportsFalse" path="canGenerateReports"
							value="false" /></td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canGenerateReportsError"
							path="canGenerateReports" cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td>Generate Waf Rules</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canGenerateWafRulesTrue" path="canGenerateWafRules"
							value="true" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canGenerateWafRulesFalse" path="canGenerateWafRules"
							value="false" /></td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canGenerateWafRulesError"
							path="canGenerateWafRules" cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Api Keys</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageApiKeysTrue" path="canManageApiKeys" value="true" />
					</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageApiKeysFalse" path="canManageApiKeys" value="false" />
					</td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageApiKeysError" path="canManageApiKeys"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Applications</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageApplicationsTrue" path="canManageApplications"
							value="true" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageApplicationsFalse" path="canManageApplications"
							value="false" /></td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageApplicationsError"
							path="canManageApplications" cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Groups</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageGroupsTrue" path="canManageGroups" value="true" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageGroupsFalse" path="canManageGroups" value="false" />
					</td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageGroupsError" path="canManageGroups"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Remote Providers</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageRemoteProvidersTrue" path="canManageRemoteProviders"
							value="true" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageRemoteProvidersFalse"
							path="canManageRemoteProviders" value="false" /></td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageRemoteProvidersError"
							path="canManageRemoteProviders" cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Roles</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageRolesTrue" path="canManageRoles" value="true" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageRolesFalse" path="canManageRoles" value="false" /></td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageRolesError" path="canManageRoles"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Teams</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageTeamsTrue" path="canManageTeams" value="true" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageTeamsFalse" path="canManageTeams" value="false" /></td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageTeamsError" path="canManageTeams"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Users</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageUsersTrue" path="canManageUsers" value="true" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageUsersFalse" path="canManageUsers" value="false" /></td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageUsersError" path="canManageUsers"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td>Manage Wafs</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageWafsTrue" path="canManageWafs" value="true" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageWafsFalse" path="canManageWafs" value="false" /></td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageWafsError" path="canManageWafs"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td>Modify Vulnerabilities</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canModifyVulnerabilitiesTrue" path="canModifyVulnerabilities"
							value="true" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canModifyVulnerabilitiesFalse"
							path="canModifyVulnerabilities" value="false" /></td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canModifyVulnerabilitiesError"
							path="canModifyVulnerabilities" cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td>Submit Defects</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canSubmitDefectsTrue" path="canSubmitDefects" value="true" />
					</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canSubmitDefectsFalse" path="canSubmitDefects" value="false" />
					</td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canSubmitDefectsError" path="canSubmitDefects"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td>Upload Scans</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canUploadScansTrue" path="canUploadScans" value="true" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canUploadScansFalse" path="canUploadScans" value="false" /></td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canUploadScansError" path="canUploadScans"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td>View Error Logs</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canViewErrorLogsTrue" path="canViewErrorLogs" value="true" />
					</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canViewErrorLogsFalse" path="canViewErrorLogs" value="false" />
					</td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canViewErrorLogsError" path="canViewErrorLogs"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td>View Job Statuses</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canViewJobStatusesTrue" path="canViewJobStatuses"
							value="true" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canViewJobStatusesFalse" path="canViewJobStatuses"
							value="false" /></td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canViewJobStatusesError"
							path="canViewJobStatuses" cssClass="errors" />
					</td>
				</tr>
			</tbody>
		</table>
		<br />
		<c:if test="${ role['new'] }">
			<input id="createRoleButton" type="submit" value="Create Role" />
		</c:if>
		<c:if test="${ not role['new'] }">
			<input id="updateRoleButton" type="submit" value="Update Role" />
		</c:if>
		<span style="padding-left: 10px"> <a id="backToRolesButton"
			href="<spring:url value="/configuration/roles"/>">Back to Roles</a>
		</span>
	</form:form>
</body>
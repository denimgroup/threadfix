<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<h4 id="myModalLabel">New Role</h4>
</div>

<div class="modal-body" id="newRoleModalBody">
	<%@ include file="/WEB-INF/views/errorMessage.jsp"%>

	<spring:url value="/configuration/roles/new" var="saveUrl"></spring:url>
	<form:form id="newRoleForm" modelAttribute="role" method="post"
			action="${fn:escapeXml(saveUrl) }">
		<table class="dataTable">
			<tbody>
				<tr>
					<td>Name</td>
					<td class="inputValue"><form:input path="displayName"
							size="70" maxlength="255" value="${ displayName }" /></td>
					<td style="padding-left: 5px"><form:errors path="displayName"
							cssClass="errors" /></td>
				</tr>
			</tbody>
		</table>
		<h3>Permissions</h3>
	
		<table class="table" style="margin-top: 5px">
			<thead>
				<tr>
					<th class="long first">Permission</th>
					<th class="short" style="text-align: center;">Yes</th>
					<th class="short last">No</th>
				</tr>
			</thead>
			<tbody>
				<tr>
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
				<tr>
					<td>Generate WAF Rules</td>
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
				<tr>
					<td>Manage API Keys</td>
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
				<tr>
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
				<tr>
					<td>Manage Defect Trackers</td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageDefectTrackersTrue" path="canManageDefectTrackers"
							value="true" /></td>
					<td class="inputValue" style="text-align: center;"><form:radiobutton
							id="canManageDefectTrackersFalse" path="canManageDefectTrackers"
							value="false" /></td>
					<td
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageDefectTrackersError"
							path="canManageDefectTrackers" cssClass="errors" />
					</td>
				</tr>
				<tr>
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
				<tr>
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
				<tr>
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
				<tr>
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
				<tr>
					<td>Manage WAFs</td>
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
				<tr>
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
				<tr>
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
				<tr>
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
				<tr>
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
				<tr>
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
	</form:form>
</div>
<div class="modal-footer">
	<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
	<a id="newRoleFormSubmitButton" class="btn btn-primary"
		onclick="javascript:submitAjaxModal('<c:out value="${ saveUrl }"/>','#newRoleForm', '#createRoleModal', '#tableDiv', '#createRoleModal');return false;">Save Role</a>
</div>
<script>
	$("#newRoleModalBody").keypress(function(e){
	    if (e.which == 13){
	        $("#newRoleFormSubmitButton").click();
	    }
	});
</script>
		

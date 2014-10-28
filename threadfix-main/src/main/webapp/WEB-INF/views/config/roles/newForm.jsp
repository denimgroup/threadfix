<script type="text/ng-template" id="newRoleModal.html">

	<div class="modal-header">
		<h4 id="myModalLabel">New Role</h4>
	</div>
	
	<div class="modal-body" id="newRoleModalBody" ng-form="form">
		<%@ include file="/WEB-INF/views/errorMessage.jsp"%>

		<table class="dataTable">
			<tbody>
				<tr>
					<td>Name</td>
					<td class="inputValue">
                        <input id="roleNameInput" type="text" name="displayName" focus-on="focusInput" ng-model="object.displayName"
                                                  size="70" maxlength="25" value="${ displayName }" required/>
                    </td>
                    <td>
                        <span id="roleNameInputRequiredError" class="errors" ng-show="form.displayName.$dirty && form.displayName.$error.required">Name is required.</span>
                        <span id="roleNameInputLengthError" class="errors" ng-show="form.displayName.$dirty && form.displayName.$error.maxlength">Maximum length is 25.</span>
                        <span id="roleNameInputNameError" class="errors" ng-show="object.displayName_error"> {{ object.displayName_error }}</span>
                    </td>
				</tr>
                <tr>
                    <td><a class="btn" ng-click="setAll('true')">Select All</a></td>
                    <td style="text-align:left; padding-left:10px;"><a class="btn" ng-click="setAll('false')">Select None</a></td>
                </tr>
			</tbody>
		</table>

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
					<td class="inputValue" style="text-align: center;"><input type="radio" 
							id="canGenerateReportsTrue" name="canGenerateReports" ng-model="object.canGenerateReports"
							value="true" /></td>
					<td class="inputValue" style="text-align: center;"><input type="radio" 
							id="canGenerateReportsFalse" name="canGenerateReports" ng-model="object.canGenerateReports"
							value="false" /></td>
					<td style="border: 0 solid black; background-color: white; padding-left: 5px">
						<form:errors id="canGenerateReportsError"
							name="canGenerateReports" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td>Generate WAF Rules</td>
					<td class="inputValue" style="text-align: center;"><input type="radio" 
							id="canGenerateWafRulesTrue" name="canGenerateWafRules" ng-model="object.canGenerateWafRules"
							value="true" /></td>
					<td class="inputValue" style="text-align: center;"><input type="radio" 
							id="canGenerateWafRulesFalse" name="canGenerateWafRules" ng-model="object.canGenerateWafRules"
							value="false" /></td>
					<td
						style="border: 0 solid black; background-color: white; padding-left: 5px">
						<form:errors id="canGenerateWafRulesError"
							name="canGenerateWafRules" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td>Manage API Keys</td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canManageApiKeys"
							id="canManageApiKeysTrue" name="canManageApiKeys" value="true" />
					</td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canManageApiKeys"
							id="canManageApiKeysFalse" name="canManageApiKeys" value="false" />
					</td>
					<td
						style="border: 0 solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageApiKeysError" name="canManageApiKeys"
							cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td>Manage Applications</td>
					<td class="inputValue" style="text-align: center;"><input type="radio" 
							id="canManageApplicationsTrue" name="canManageApplications" ng-model="object.canManageApplications"
							value="true" /></td>
					<td class="inputValue" style="text-align: center;"><input type="radio" 
							id="canManageApplicationsFalse" name="canManageApplications" ng-model="object.canManageApplications"
							value="false" /></td>
					<td
						style="border: 0 solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageApplicationsError"
							name="canManageApplications" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td>Manage Defect Trackers</td>
					<td class="inputValue" style="text-align: center;"><input type="radio" 
							id="canManageDefectTrackersTrue" name="canManageDefectTrackers" ng-model="object.canManageDefectTrackers"
							value="true" /></td>
					<td class="inputValue" style="text-align: center;"><input type="radio" 
							id="canManageDefectTrackersFalse" name="canManageDefectTrackers" ng-model="object.canManageDefectTrackers"
							value="false" /></td>
					<td
						style="border: 0 solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageDefectTrackersError"
							name="canManageDefectTrackers" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td>Manage Remote Providers</td>
					<td class="inputValue" style="text-align: center;"><input type="radio" 
							id="canManageRemoteProvidersTrue" name="canManageRemoteProviders" ng-model="object.canManageRemoteProviders"
							value="true" /></td>
					<td class="inputValue" style="text-align: center;"><input type="radio" 
							id="canManageRemoteProvidersFalse" ng-model="object.canManageRemoteProviders"
							name="canManageRemoteProviders" value="false" /></td>
					<td
						style="border: 0 solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageRemoteProvidersError"
							name="canManageRemoteProviders" cssClass="errors" />
					</td>
				</tr>
                <tr>
                    <td>Manage Scan Agents</td>
                    <td class="inputValue" style="text-align: center;"><input type="radio"
                                                                              id="canManageScanAgentsTrue" name="canManageScanAgents" ng-model="object.canManageScanAgents"
                                                                              value="true" /></td>
                    <td class="inputValue" style="text-align: center;"><input type="radio"
                                                                              id="canManageScanAgentsFalse" ng-model="object.canManageScanAgents"
                                                                              name="canManageScanAgents" value="false" /></td>
                    <td style="border: 0 solid black; background-color: white; padding-left: 5px">
                        <form:errors id="canManageScanAgentsError"
                                     name="canManageScanAgents" cssClass="errors" />
                    </td>
                </tr>
                <tr>
                    <td>Manage System Settings</td>
                    <td class="inputValue" style="text-align: center;"><input type="radio"
                                                                              id="canManageSystemSettingsTrue" name="canManageSystemSettings" ng-model="object.canManageSystemSettings"
                                                                              value="true" /></td>
                    <td class="inputValue" style="text-align: center;"><input type="radio"
                                                                              id="canManageSystemSettingsFalse" ng-model="object.canManageSystemSettings"
                                                                              name="canManageSystemSettings" value="false" /></td>
                    <td style="border: 0 solid black; background-color: white; padding-left: 5px">
                        <form:errors id="canManageSystemSettingsError"
                                     name="canManageSystemSettings" cssClass="errors" />
                    </td>
                </tr>
				<tr>
					<td>Manage Roles</td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canManageRoles"
							id="canManageRolesTrue" name="canManageRoles" value="true" /></td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canManageRoles"
							id="canManageRolesFalse" name="canManageRoles" value="false" /></td>
					<td
						style="border: 0 solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageRolesError" name="canManageRoles"
							cssClass="errors" />
					</td>
				</tr>
                <tr>
                    <td>Manage Tags</td>
                    <td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canManageTags"
                                                                              id="canManageTagsTrue" name="canManageTags" value="true" /></td>
                    <td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canManageTags"
                                                                              id="canManageTagsFalse" name="canManageTags" value="false" /></td>
                    <td style="border: 0 solid black; background-color: white; padding-left: 5px">
                        <form:errors id="canManageTagsError" name="canManageTags" cssClass="errors" />
                    </td>
                </tr>
				<tr>
					<td>Manage Teams</td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canManageTeams"
							id="canManageTeamsTrue" name="canManageTeams" value="true" /></td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canManageTeams"
							id="canManageTeamsFalse" name="canManageTeams" value="false" /></td>
					<td
						style="border: 0 solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageTeamsError" name="canManageTeams"
							cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td>Manage Users</td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canManageUsers"
							id="canManageUsersTrue" name="canManageUsers" value="true" /></td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canManageUsers"
							id="canManageUsersFalse" name="canManageUsers" value="false" /></td>
					<td
						style="border: 0 solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageUsersError" name="canManageUsers"
							cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td>Manage WAFs</td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canManageWafs"
							id="canManageWafsTrue" name="canManageWafs" value="true" /></td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canManageWafs"
							id="canManageWafsFalse" name="canManageWafs" value="false" /></td>
					<td
						style="border: 0 solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageWafsError" name="canManageWafs"
							cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td>Modify Vulnerabilities</td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canModifyVulnerabilities"
							id="canModifyVulnerabilitiesTrue" name="canModifyVulnerabilities"
							value="true" /></td>
					<td class="inputValue" style="text-align: center;"><input type="radio"
							id="canModifyVulnerabilitiesFalse" ng-model="object.canModifyVulnerabilities"
							name="canModifyVulnerabilities" value="false" /></td>
					<td
						style="border: 0 solid black; background-color: white; padding-left: 5px">
						<form:errors id="canModifyVulnerabilitiesError"
							name="canModifyVulnerabilities" cssClass="errors" />
					</td>
				</tr>
                <tr>
                    <td>Manage Vulnerability Filters</td>
                    <td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canManageVulnFilters"
                                                                              id="canManageVulnFiltersTrue" name="canManageVulnFilters"
                                                                              value="true" /></td>
                    <td class="inputValue" style="text-align: center;"><input type="radio"
                                                                              id="canManageVulnFiltersFalse" ng-model="object.canManageVulnFilters"
                                                                              name="canManageVulnFilters" value="false" /></td>
                    <td
                            style="border: 0 solid black; background-color: white; padding-left: 5px">
                        <form:errors id="canManageVulnFiltersError"
                                     name="canManageVulnFilters" cssClass="errors" />
                    </td>
                </tr>
				<tr>
					<td>Submit Defects</td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canSubmitDefects"
							id="canSubmitDefectsTrue" name="canSubmitDefects" value="true" />
					</td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canSubmitDefects"
							id="canSubmitDefectsFalse" name="canSubmitDefects" value="false" />
					</td>
				</tr>
				<tr>
					<td>Upload Scans</td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canUploadScans"
							id="canUploadScansTrue" name="canUploadScans" value="true" /></td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canUploadScans"
							id="canUploadScansFalse" name="canUploadScans" value="false" /></td>
				</tr>
				<tr>
					<td>View Error Logs</td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canViewErrorLogs"
							id="canViewErrorLogsTrue" name="canViewErrorLogs" value="true" />
					</td>
					<td class="inputValue" style="text-align: center;"><input type="radio"  ng-model="object.canViewErrorLogs"
							id="canViewErrorLogsFalse" name="canViewErrorLogs" value="false" />
					</td>
				</tr>
				<!--<tr>-->
					<!--<td>View Job Statuses</td>-->
					<!--<td class="inputValue" style="text-align: center;"><input type="radio" -->
							<!--id="canViewJobStatusesTrue" name="canViewJobStatuses" ng-model="object.canViewJobStatuses"-->
							<!--value="true" /></td>-->
					<!--<td class="inputValue" style="text-align: center;"><input type="radio" -->
							<!--id="canViewJobStatusesFalse" name="canViewJobStatuses" ng-model="object.canViewJobStatuses"-->
							<!--value="false" /></td>-->
				<!--</tr>-->
			</tbody>
		</table>
	</div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>

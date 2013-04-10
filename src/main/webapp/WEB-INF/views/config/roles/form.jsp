<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<button type="button" class="close" data-dismiss="modal"
		aria-hidden="true">X</button>
	<h4 id="myModalLabel">Edit Role</h4>
</div>

<div class="modal-body">
	<%@ include file="/WEB-INF/views/errorMessage.jspf"%>

	<spring:url value="/configuration/roles/{roleId}/edit" var="saveEditUrl">
		<spring:param name="roleId" value="${ editRole.id }"/>
	</spring:url>
	<form:form id="roleEditForm${ status.count }" modelAttribute="editRole" method="post"
			action="${fn:escapeXml(saveEditUrl) }">
		<table class="dataTable">
			<tbody>
				<tr>
					<td class="no-color">Name:</td>
					<td class="no-color inputValue"><form:input path="displayName"
							size="70" maxlength="255" value="${ editRole.displayName }" /></td>
					<td class="no-color" style="padding-left: 5px"><form:errors path="displayName"
							cssClass="errors" /></td>
				</tr>
			</tbody>
		</table>
		<h3>Permissions</h3>
	
		<table class="table table-striped" style="margin-top: 5px">
			<thead>
				<tr>
					<th class="long first">Permission</th>
					<th class="short" style="text-align: center;">Yes</th>
					<th class="short last">No</th>
				</tr>
			</thead>
			<tbody>
				<tr class="bodyRow">
					<td class="no-color">Generate Reports</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canGenerateReports }">checked="checked"</c:if>
							id="canGenerateReportsTrue" name="canGenerateReports"
							value="true" /></td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canGenerateReports }">checked="checked"</c:if>
							id="canGenerateReportsFalse" name="canGenerateReports"
							value="false" /></td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canGenerateReportsError"
							name="canGenerateReports" cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td class="no-color">Generate WAF Rules</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canGenerateWafRules }">checked="checked"</c:if>
							id="canGenerateWafRulesTrue" name="canGenerateWafRules"
							value="true" /></td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canGenerateWafRules }">checked="checked"</c:if>
							id="canGenerateWafRulesFalse" name="canGenerateWafRules"
							value="false" /></td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canGenerateWafRulesError"
							name="canGenerateWafRules" cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td class="no-color">Manage API Keys</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canManageApiKeys }">checked="checked"</c:if>
							id="canManageApiKeysTrue" name="canManageApiKeys" value="true" />
					</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canManageApiKeys }">checked="checked"</c:if>
							id="canManageApiKeysFalse" name="canManageApiKeys" value="false" />
					</td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageApiKeysError" name="canManageApiKeys"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td class="no-color">Manage Applications</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canManageApplications }">checked="checked"</c:if>
							id="canManageApplicationsTrue" name="canManageApplications"
							value="true" /></td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canManageApplications }">checked="checked"</c:if>
							id="canManageApplicationsFalse" name="canManageApplications"
							value="false" /></td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageApplicationsError"
							name="canManageApplications" cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td class="no-color">Manage Defect Trackers</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canManageDefectTrackers }">checked="checked"</c:if>
							id="canManageDefectTrackersTrue" name="canManageDefectTrackers"
							value="true" /></td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canManageDefectTrackers }">checked="checked"</c:if>
							id="canManageDefectTrackersFalse" name="canManageDefectTrackers"
							value="false" /></td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageDefectTrackersError"
							name="canManageDefectTrackers" cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td class="no-color">Manage Remote Providers</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canManageRemoteProviders }">checked="checked"</c:if>
							id="canManageRemoteProvidersTrue" name="canManageRemoteProviders"
							value="true" /></td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canManageRemoteProviders }">checked="checked"</c:if>
							id="canManageRemoteProvidersFalse"
							name="canManageRemoteProviders" value="false" /></td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageRemoteProvidersError"
							name="canManageRemoteProviders" cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td class="no-color">Manage Roles</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canManageRoles }">checked="checked"</c:if>
							id="canManageRolesTrue" name="canManageRoles" value="true" /></td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canManageRoles }">checked="checked"</c:if>
							id="canManageRolesFalse" name="canManageRoles" value="false" /></td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageRolesError" name="canManageRoles"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td class="no-color">Manage Teams</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canManageTeams }">checked="checked"</c:if>
							id="canManageTeamsTrue" name="canManageTeams" value="true" /></td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canManageTeams }">checked="checked"</c:if>
							id="canManageTeamsFalse" name="canManageTeams" value="false" /></td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageTeamsError" name="canManageTeams"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td class="no-color">Manage Users</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canManageUsers }">checked="checked"</c:if>
							id="canManageUsersTrue" name="canManageUsers" value="true" /></td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canManageUsers }">checked="checked"</c:if>
							id="canManageUsersFalse" name="canManageUsers" value="false" /></td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageUsersError" name="canManageUsers"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td class="no-color">Manage WAFs</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canManageWafs }">checked="checked"</c:if>
							id="canManageWafsTrue" name="canManageWafs" value="true" /></td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canManageWafs }">checked="checked"</c:if>
							id="canManageWafsFalse" name="canManageWafs" value="false" /></td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canManageWafsError" name="canManageWafs"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td class="no-color">Modify Vulnerabilities</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canModifyVulnerabilities }">checked="checked"</c:if>
							id="canModifyVulnerabilitiesTrue" name="canModifyVulnerabilities"
							value="true" /></td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canModifyVulnerabilities }">checked="checked"</c:if>
							id="canModifyVulnerabilitiesFalse"
							name="canModifyVulnerabilities" value="false" /></td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canModifyVulnerabilitiesError"
							name="canModifyVulnerabilities" cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td class="no-color">Submit Defects</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canSubmitDefects }">checked="checked"</c:if>
							id="canSubmitDefectsTrue" name="canSubmitDefects" value="true" />
					</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canSubmitDefects }">checked="checked"</c:if>
							id="canSubmitDefectsFalse" name="canSubmitDefects" value="false" />
					</td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canSubmitDefectsError" name="canSubmitDefects"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td class="no-color">Upload Scans</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canUploadScans }">checked="checked"</c:if>
							id="canUploadScansTrue" name="canUploadScans" value="true" /></td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canUploadScans }">checked="checked"</c:if>
							id="canUploadScansFalse" name="canUploadScans" value="false" /></td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canUploadScansError" name="canUploadScans"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td class="no-color">View Error Logs</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canViewErrorLogs }">checked="checked"</c:if>
							id="canViewErrorLogsTrue" name="canViewErrorLogs" value="true" />
					</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canViewErrorLogs }">checked="checked"</c:if>
							id="canViewErrorLogsFalse" name="canViewErrorLogs" value="false" />
					</td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canViewErrorLogsError" name="canViewErrorLogs"
							cssClass="errors" />
					</td>
				</tr>
				<tr class="bodyRow">
					<td class="no-color">View Job Statuses</td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ editRole.canViewJobStatuses }">checked="checked"</c:if>
							id="canViewJobStatusesTrue" name="canViewJobStatuses"
							value="true" /></td>
					<td class="no-color inputValue" style="text-align: center;">
						<input type="radio" <c:if test="${ not editRole.canViewJobStatuses }">checked="checked"</c:if>
							id="canViewJobStatusesFalse" name="canViewJobStatuses"
							value="false" /></td>
					<td class="no-color"
						style="border: 0px solid black; background-color: white; padding-left: 5px">
						<form:errors id="canViewJobStatusesError"
							name="canViewJobStatuses" cssClass="errors" />
					</td>
				</tr>
			</tbody>
		</table>
	</form:form>
</div>
<div class="modal-footer">
	<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
	<a id="submitRemoteProviderFormButton${ remoteProviderType.id }" class="btn btn-primary" 
		onclick="javascript:submitAjaxModal('<c:out value="${ saveEditUrl }"/>','#roleEditForm${ status.count }', '#editRoleModal${ status.count }', '#tableDiv', '#editRoleModal${ status.count }');return false;">Save Role</a>
</div>

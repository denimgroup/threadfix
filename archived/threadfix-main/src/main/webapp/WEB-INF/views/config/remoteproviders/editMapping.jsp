<script type="text/ng-template" id="editRemoteProviderApplicationMapping.html">

    <div class="modal-header">
        <h4 id="myModalLabel">
            Edit Mapping for {{ object.customName || object.nativeName || object.nativeId }}
            <span ng-show="config.showDelete" class="delete-span">
                <a class="btn btn-danger header-button deleteLink"
                        id="deleteLink${ remoteProviderApplication.id }"
                        ng-click="showDeleteDialog('mapping')">
                    Delete
                </a>
            </span>
        </h4>
    </div>

	<div ng-form="form" class="modal-body">
		<table style="border-spacing:10px" class="modal-form-table">
			<tbody>
				<tr>
					<td>Team</td>
					<td>
                        <select id="orgSelect1" ng-options="team.name for team in config.teams" name="teamName"
                                ng-model="object.organization"
                                ng-change="object.application = object.organization.applications[0]" required>

                        </select>
                    </td>
                    <td>
                        <span class="errors" ng-show="form.teamName.$dirty && form.teamName.$error.required">Team is required.</span>
                    </td>
				</tr>
				<tr>
					<td style="padding-right:10px">Application</td>
					<td>
                        <select id="appSelect1" ng-model="object.application" required name="appName"
                                ng-options="app.name for app in object.organization.applications">
                        </select>
                    </td>
                    <td>
                        <span class="errors" ng-show="form.appName.$dirty && form.appName.$error.required">Application is required.</span>
                    </td>
				</tr>
			</tbody>
		</table>
	</div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
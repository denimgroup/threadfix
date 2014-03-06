<script type="text/ng-template" id="editRemoteProviderApplicationMapping.html">

    <div class="modal-header">
        <h4 id="myModalLabel">
            Edit Mapping for {{ object.nativeId }}
            <span ng-show="config.showDelete" class="delete-span">
                <a class="btn btn-danger header-button deleteLink"
                        id="deleteLink${ remoteProviderApplication.id }"
                        ng-click="showDeleteDialog('mapping')">
                    Delete
                </a>
            </span>
        </h4>
    </div>

    <!-- TODO re-add IDs -->
	<div ng-form="form" class="modal-body">
		<table style="border-spacing:10" class="modal-form-table">
			<tbody>
				<tr>
					<td>Team</td>
					<td>
                        <select ng-options="team.name for team in config.teams"
                                ng-model="object.organization"
                                ng-change="object.application.id = object.organization.applications[0].id">

                        </select>
                    </td>
				</tr>
				<tr>
					<td style="padding-right:10px">Application</td>
					<td>
                        <select ng-model="object.application.id">
                            <option ng-repeat="app in object.organization.applications" value="{{ app.id }}">{{ app.name }}</option>
                        </select>
                    </td>
				</tr>
			</tbody>
		</table>
	</div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
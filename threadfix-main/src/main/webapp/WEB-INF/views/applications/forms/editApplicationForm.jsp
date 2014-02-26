<script type="text/ng-template" id="editApplicationModal.html">

	<div class="modal-header">
		<h4 id="myModalLabel">Edit Application
			<span class="delete-span">
				<a class="btn btn-danger header-button" id="deleteLink" href="{{ config.application.id }} + 'delete' + {{ csrfToken }}"
						onclick="return confirm('Are you sure you want to delete the application?')">
					Delete
				</a>
			</span>
		</h4>
	</div>
	<div ng-form="form" class="modal-body">
		<table class="modal-form-table">
            <tr>
                <td>Name</td>
                <td>
                    <input focus-on="focusInput" type='text' name='name' ng-model="object.name" required/>
                </td>
                <td>
                    <span class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                </td>
            </tr>
            <tr>
                <td>URL</td>
                <td>
                    <input type='url' name='url' ng-model="object.url"/>
                    <span class="errors" ng-show="form.url.$dirty && form.url.$error.maxlength">Maximum length is 200.</span>
                </td>
            </tr>
            <tr>
                <td>Unique ID</td>
                <td>
                    <input name="uniqueId" type='text'
                           ng-model="object.uniqueId"
                           id="uniqueIdInput{{ object.team.id }}" size="50" maxlength="255"/>
                </td>
            </tr>
			<tr>
				<td>Team</td>
				<td>
					<select ng-model="object.team.id" id="organizationId" name="organization.id">
						<option ng-selected="team.id === object.team.id"
                                ng-repeat="team in config.teams"
                                value="{{ team.id }}">
                            {{ team.name }}
                        </option>
					</select>
					<errors name="organization.id" cssClass="errors" />
				</td>																
			</tr>
			<tr>
				<td>Criticality</td>
				<td>
					<select ng-model="object.applicationCriticality.id" id="criticalityId" name="applicationCriticality.id">
						<option ng-selected="criticality.id === object.applicationCriticality.id"
                                ng-repeat="criticality in config.applicationCriticalityList"
                                value="{{ criticality.id }}">
                            {{ criticality.name }}
                        </option>
					</select>
				</td>
			</tr>
			<tr>
				<td class="right-align">Application Type</td>
				<td >
					<select
                            ng-model="object.frameworkType"
                            name="frameworkType">
                        <option ng-selected="type === object.frameworkType"
                                ng-repeat="type in config.applicationTypes"
                                value="{{ type }}">
                            {{ type }}
                        </option>
                    </select>
				</td>
			</tr>
            <tr>
                <td class="right-align">Source Code URL</td>
                <td >
                    <input name="repositoryUrl"
                           type='url' id="repositoryUrl"
                           maxlength="250"
                           ng-model="object.repositoryUrl"/>
                </td>
            </tr>
            <tr>
                <td class="right-align">Source Code Folder</td>
                <td >
                    <input name="repositoryFolder"
                           type='text' id="repositoryFolder"
                           maxlength="250" ng-model="object.repositoryFolder"/>
                </td>
            </tr>
			<tr id="appDTDiv" data-json-test-url="<c:out value="${ testUrl }"/>">
				<%@ include file="/WEB-INF/views/applications/defectTrackerRow.jsp" %>
			</tr>
			<tr id="appWafDiv">
				<%@ include file="/WEB-INF/views/applications/wafRow.jsp" %>
			</tr>
			
		</table>
	</div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
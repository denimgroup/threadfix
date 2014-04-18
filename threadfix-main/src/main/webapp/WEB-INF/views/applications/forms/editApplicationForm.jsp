<script type="text/ng-template" id="editApplicationModal.html">

	<div class="modal-header">
		<h4 id="myModalLabel">Edit Application
			<span class="delete-span">
				<a class="btn btn-danger header-button" id="deleteLink" href="{{ config.application.deleteUrl }}"
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
                    <span class="errors" ng-show="object.name_error"> {{ object.name_error }}</span>
                </td>
            </tr>
            <tr>
                <td>URL</td>
                <td>
                    <input type='url' name='url' ng-model="object.url" ng-maxlength="255"/>
                    <span class="errors" ng-show="form.url.$dirty && form.url.$error.maxlength">Maximum length is 255.</span>
                    <span class="errors" ng-show="form.url.$dirty && form.url.$error.url">URL is invalid.</span>
                </td>
            </tr>
            <tr>
                <td>Unique ID</td>
                <td>
                    <input name="uniqueId" type='text'
                           ng-model="object.uniqueId"
                           id="uniqueIdInput{{ object.team.id }}" size="50" maxlength="255"/>
                    <span class="errors" ng-show="form.uniqueId.$dirty && form.uniqueId.$error.maxlength">Maximum length is 255.</span>
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
                    <span class="errors" ng-show="object.applicationCriticality_id_error"> {{ object.applicationCriticality_id_error }}</span>
				</td>
			</tr>
            <tr>
                <td>Source Code Revision</td>
                <td>
                    <input type="text" id="repositoryBranch" ng-model="object.repositoryBranch" maxlength="250" name="repositoryBranch"/>
                    <span class="errors" ng-show="form.repositoryBranch.$dirty && form.repositoryBranch.$error.maxlength">Maximum length is 250.</span>
                </td>
            </tr>
            <tr>
                <td>Source Code UserName</td>
                <td>
                    <input type="text" id="repositoryUsername" ng-model="object.repositoryUserName" maxlength="250" name="repositoryUserName"/>
                    <span class="errors" ng-show="form.repositoryUserName.$dirty && form.repositoryUserName.$error.maxlength">Maximum length is 250.</span>
                </td>
            </tr>
            <tr>
                <td>Source Code Password</td>
                <td>
                    <input type="password" id="repositoryPassword" ng-model="object.repositoryPassword" showPassword="true" maxlength="250" path="repositoryPassword"/>
                    <span class="errors" ng-show="form.repositoryPassword.$dirty && form.repositoryPassword.$error.maxlength">Maximum length is 250.</span>
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
                           maxlength="255"
                           ng-model="object.repositoryUrl"/>
                    <span class="errors" ng-show="form.repositoryUrl.$dirty && form.repositoryUrl.$error.maxlength">Maximum length is 255.</span>
                    <span class="errors" ng-show="form.repositoryUrl.$dirty && form.repositoryUrl.$error.url">URL is invalid.</span>
                </td>
            </tr>
            <tr>
                <td class="right-align">Source Code Folder</td>
                <td >
                    <input name="repositoryFolder"
                           type='text' id="repositoryFolder"
                           maxlength="250" ng-model="object.repositoryFolder"/>
                    <span class="errors" ng-show="form.repositoryFolder.$dirty && form.repositoryFolder.$error.maxlength">Maximum length is 250.</span>
                    <span class="errors" ng-show="object.repositoryFolder_error"> {{ object.repositoryFolder_error }}</span>
                </td>
            </tr>
			<tr id="appDTDiv" data-json-test-url="<c:out value="${ testUrl }"/>">
                <td>WAF</td>
                <!-- TODO make this a link -->
                <td ng-show="object.waf">{{ object.waf.name }}</td>
                <td><button class="btn" ng-click="switchTo('addWaf')">Set WAF</button></td>
			</tr>
			<tr id="appWafDiv">
                <td>Defect Tracker</td>
                <!-- TODO make this a link -->
                <td ng-show="object.defectTracker">{{ object.defectTracker.name }}</td>
                <td><button class="btn" ng-click="switchTo('addDefectTracker')">Set Defect Tracker</button></td>
			</tr>
			
		</table>
	</div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>

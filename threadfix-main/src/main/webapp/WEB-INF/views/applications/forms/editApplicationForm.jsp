<script type="text/ng-template" id="editApplicationModal.html">

	<div class="modal-header">
		<h4 id="myModalLabel">Edit Application
			<span class="delete-span">
                <!-- TODO remove onclick handler in favor of angular -->
				<a class="btn btn-danger header-button" id="deleteLink" href="{{ config.application.deleteUrl }}"
						onclick="return confirm('Are you sure you want to delete the application?')">
					Delete
				</a>
			</span>
		</h4>
	</div>
	<div ng-form="form" class="modal-body">
        <!-- TODO move most of this to a shared component -->
		<table class="modal-form-table">
            <tr>
                <td>Name</td>
                <td>
                    <input id="nameInput" focus-on="focusInput" type='text' name='name' ng-model="object.name" ng-maxlength="60" required/>
                </td>
                <td>
                    <span id="applicationNameInputRequiredError" class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                    <span id="applicationNameInputLengthError" class="errors" ng-show="form.name.$dirty && form.name.$error.maxlength">Maximum length is 60.</span>
                    <span id="applicationNameInputNameError" class="errors" ng-show="object.name_error"> {{ object.name_error }}</span>
                </td>
            </tr>
            <tr>
                <td>URL</td>
                <td>
                    <input id="urlInput" type='url' name='url' ng-model="object.url" ng-maxlength="255"/>
                </td>
                <td>
                    <span id="applicationUrlInputLengthError" class="errors" ng-show="form.url.$dirty && form.url.$error.maxlength">Maximum length is 255.</span>
                    <span id="applicationUrlInputInvalidUrlError" class="errors" ng-show="form.url.$dirty && form.url.$error.url">URL is invalid.</span>
                </td>
            </tr>
            <tr>
                <td>Unique ID</td>
                <td>
                    <input name="uniqueId" type='text'
                           ng-model="object.uniqueId"
                           id="uniqueIdInput" size="50" maxlength="255"/>
                </td>
                <td>
                    <span id="uniqueIdLengthError" class="errors" ng-show="form.uniqueId.$dirty && form.uniqueId.$error.maxlength">Maximum length is 255.</span>
                </td>
            </tr>
			<tr>
				<td>Team</td>
				<td>
					<select ng-model="object.organization.id" id="organizationId" name="organization.id">
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
                <td>
                    <span class="errors" ng-show="object.applicationCriticality_id_error"> {{ object.applicationCriticality_id_error }}</span>
				</td>
			</tr>
            <tr>
                <td class="right-align">Application Type</td>
                <td >
                    <select id="frameworkType"
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
                <td class="right-align">Tag</td>
                <td class="left-align" >
                    <multi-select id="tagSelect"
                            input-model="config.tags"
                            output-model="object.tags"
                            button-label="name"
                            item-label="name"
                            tick-property="selected"
                            >
                    </multi-select>
                </td>
            </tr>

            <tr>
                <td colspan="2">
                    <a class="pointer" ng-click="sourceCodeDisplay = !sourceCodeDisplay">Source Code Information</a>
                </td>
            </tr>
            <tr ng-show="sourceCodeDisplay">
                <td class="right-align">Source Code URL</td>
                <td class="left-align" >
                    <input name="repositoryUrl"
                           type='url' id="repositoryUrl"
                           maxlength="255" ng-model="object.repositoryUrl"/>
                </td>
                <td>
                    <span id="sourceUrlLengthError" class="errors" ng-show="form.repositoryUrl.$dirty && form.repositoryUrl.$error.maxlength">Maximum length is 255.</span>
                    <span id="sourceUrlValidError" class="errors" ng-show="form.repositoryUrl.$dirty && form.repositoryUrl.$error.url">URL is invalid.</span>
                </td>
            </tr>
            <tr ng-show="sourceCodeDisplay">
                <td>Source Code Revision</td>
                <td>
                    <input type="text" id="repositoryBranch" ng-model="object.repositoryBranch" maxlength="250" name="repositoryBranch"/>
                </td>
                <td>
                    <span id="sourceRevisionLengthError" class="errors" ng-show="form.repositoryBranch.$dirty && form.repositoryBranch.$error.maxlength">Maximum length is 250.</span>
                </td>
            </tr>
            <tr ng-show="sourceCodeDisplay">
                <td>Source Code User Name</td>
                <td>
                    <input type="text" id="repositoryUsername" ng-model="object.repositoryUserName" maxlength="250" name="repositoryUserName"/>
                </td>
                <td>
                    <span id="sourceUserNameLengthError" class="errors" ng-show="form.repositoryUserName.$dirty && form.repositoryUserName.$error.maxlength">Maximum length is 250.</span>
                </td>
            </tr>
            <tr ng-show="sourceCodeDisplay">
                <td>Source Code Password</td>
                <td>
                    <input autocomplete="off" type="password" id="repositoryPassword" ng-model="object.repositoryPassword" showPassword="true" maxlength="250" name="repositoryPassword"/>
                </td>
                <td>
                    <span id="sourcePasswordLengthError" class="errors" ng-show="form.repositoryPassword.$dirty && form.repositoryPassword.$error.maxlength">Maximum length is 250.</span>
                </td>
            </tr>
            <tr ng-show="sourceCodeDisplay">
                <td class="right-align">Source Code Folder</td>
                <td class="left-align" >
                    <input name="repositoryFolder"
                           type='text' id="repositoryFolderInput"
                           maxlength="250" ng-model="object.repositoryFolder"/>
                </td>
                <td>
                    <span id="sourceFolderLengthError" class="errors" ng-show="form.repositoryFolder.$dirty && form.repositoryFolder.$error.maxlength">Maximum length is 250.</span>
                    <span id="sourceFolderOtherError" class="errors" ng-show="object.repositoryFolder_error"> {{ object.repositoryFolder_error }}</span>
                </td>
            </tr>
			<tr id="appDTDiv">
                <td>WAF</td>
                <td id="wafName" ng-show="object.waf" class="pointer">
                    <a id="wafNameText" ng-click="switchTo('goToWaf')">
                        {{ object.waf.name }}
                    </a>
                </td>
                <td><button class="btn" ng-click="switchTo('addWaf')" id="addWafButton">Set WAF</button></td>
			</tr>
			<tr id="appWafDiv">
                <td>Defect Tracker</td>
                <td id="defectTrackerName" ng-show="object.defectTracker">
                    <a id="linkDT" ng-href="{{object.defectTracker.url}}" class="pointer" target='_blank'>{{ object.defectTracker.name }}</a>
                </td>
                <td><button id="addDefectTrackerButton" class="btn" ng-click="switchTo('addDefectTracker')">Set Defect Tracker</button></td>
			</tr>
            <tr>
                <td>
                    Disable Vulnerability Merging
                </td>
                <td class="inputValue">
                    <input id="skipApplicationMerge" type="checkbox" ng-model="object.skipApplicationMerge" name="skipApplicationMerge"/>
                    <a class="btn" popover="ThreadFix detects matching scan results and combine them in order to simplify the result set. This can make the number of vulnerabilities in ThreadFix lower than the number of results in a scan. Checking this box disables this behavior.">?</a>
                </td>
            </tr>
		</table>
	</div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>

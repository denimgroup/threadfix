<script type="text/ng-template" id="submitDefectForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            Submit Defect
        </h4>
    </div>
    <div ng-form="form" class="modal-body">
        <div ng-hide="initialized" class="modal-spinner-div"><span class="spinner dark"></span>Loading</div>
        <div id="load-profile-defaults" ng-show="initialized && defaultProfiles.length > 0 " >
            <select ng-options="profile.id as profile.name for profile in defaultProfiles"
                    ng-model="defectDefaultsConfig.selectedDefaultProfileId"
                    ng-change="loadProfileDefaults()" >
                <option value="">Load defaults from profile</option>
            </select>
            <span ng-show="loadingProfileDefaults" class="spinner dark"></span>
        </div>

        <div class="dynamic-defect-form" ng-if="isDynamicForm">
            <span ng-if="stdFormTemplate && hasFields" class="errors">* required field</span>
            <dynamic-form ng-if="stdFormTemplate" template="stdFormTemplate"
                          ng-model="fieldsMap">
            </dynamic-form>
            <div class="defect-form-row">
                <a type="button" class="btn" href="#" ng-click="showMoreInformation = !showMoreInformation">
                    More Information
                </a>
            </div>
            <div class="defect-form-row" ng-show="showMoreInformation">
                This option will add the scanner description field to the defect description body.
                For more information about configuration the defect description body, please visit
                <a href="https://github.com/denimgroup/threadfix/wiki/CustomizeDefectDescriptions" target="_blank">
                    the wiki page
                </a>.
            </div>
        </div>

        <div ng-if="!isDynamicForm">

            <table ng-show="initialized" class="dataTable" style="text-align: left">
                <tbody>
                    <tr ng-show="config.typeName === 'Version One' || config.typeName === 'Bugzilla' || config.typeName === 'Jira'">
                        <td ng-show="config.typeName === 'Version One'">Sprint</td>
                        <td ng-show="config.typeName === 'Bugzilla' || config.typeName === 'Jira'">Component</td>
                        <td class="inputValue">
                            <select ng-model="object.selectedComponent" name="selectedComponent" ng-options="component for component in config.components"></select>
                        </td>
                    </tr>
                    <tr>
                        <td>Priority</td>
                        <td class="inputValue">
                            <select ng-model="object.priority" name="priority" ng-options="priority for priority in config.priorities"></select>
                        </td>
                    </tr>
                    <tr>
                        <td>Status</td>
                        <td class="inputValue">
                            <select ng-model="object.status" name="status" ng-options="status for status in config.statuses"></select>
                        </td>
                    </tr>
                    <tr ng-show="config.typeName === 'Bugzilla' || config.typeName === 'HP Quality Center'">
                        <td>Version</td>
                        <td class="inputValue">
                            <select ng-model="object.version" name="version" ng-options="version for version in config.versions"></select>
                        </td>
                    </tr>
                    <tr ng-show="config.typeName === 'Bugzilla' || config.typeName === 'HP Quality Center'">
                        <td>Severity</td>
                        <td class="inputValue">
                            <select ng-model="object.severity" name="severity" ng-options="severity for severity in config.severities"></select>
                        </td>
                    </tr>
                    <tr>
                        <td>Title</td>
                        <td colspan="5" class="inputValue">
                            <input focus-on="focusInput" required style="width:549px;" type="text" ng-model="object.summary" name="summary"/>
                        </td>
                    </tr>
                    <tr>
                        <td>Include Scanner Detail</td>
                        <td class="inputValue">
                            <input ng-model="object.additionalScannerInfo" name="additionalScannerInfo" type="checkbox"/>
                        </td>
                    </tr>
                    <tr style="margin-top:5px;">
                        <td>Description</td>
                        <td colspan="5" class="inputValue">
                            <textarea name="preamble" ng-model="object.preamble" style="width:549px; height:100px;"></textarea>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <%@ include file="../vulnerabilities/littleVulnTable.jspf" %>
    </div>
    <div class="modal-footer">
        <span class="errors" style="float:left">{{ errorMessage }}</span>

        <a class="btn" ng-click="cancel()">Close</a>
        <button id="loadingButton"
                disabled="disabled"
                class="btn btn-primary"
                ng-show="loading">
            <span class="spinner"></span>
            Submitting
        </button>
        <button id="submit"
                ng-if="hasFields"
                ng-class="{ disabled : form.$invalid }"
                class="btn btn-primary"
                ng-mouseenter="form.summary.$dirty = true"
                ng-hide="loading"
                ng-click="ok(form)">Submit Defect</button>
    </div>
</script>

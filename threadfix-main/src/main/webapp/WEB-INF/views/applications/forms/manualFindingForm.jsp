<script type="text/ng-template" id="manualFindingForm.html">
	<div class="modal-header">
		<h4>Manual Finding</h4>
	</div>
	<div ng-form="form" class="modal-body">
        <table class="modal-form-table">
            <tbody>
                <tr>
                    <td>
                        <input style="margin-right:5px" ng-model="object.group" id="dynamicRadioButton" type="radio" name="group" value="dynamic" checked>Dynamic
                    </td>
                    <td>
                        <input style="margin-right:5px" ng-model="object.group" id="staticRadioButton" type="radio" name="group" value="static">Static
                    </td>
                </tr>
                <tr>
                    <td>CWE</td>
                    <td class="inputValue">
                        <input required
                               type="text"
                               ng-model="object.channelVulnerability.code"
                               name="channelVulnerabilityCode"
                               class="form-control"
                               id="txtSearch"
                               style="width:300px"
                               typeahead="vulnerability.name for vulnerability in config.manualChannelVulnerabilities | filter:$viewValue | limitTo:10"/>
                    </td>
                    <td>
                        <span class="errors" ng-show="form.channelVulnerabilityCode.$dirty && form.channelVulnerabilityCode.$error.required">CWE is required.</span>
                        <span class="errors" ng-show="object.channelVulnerability_code_error">{{ object.channelVulnerability_code_error }}</span>
                    </td>
                </tr>
                <tr ng-show="object.group === 'dynamic'">
                    <td>URL</td>
                    <td style="padding:5px;" class="inputValue">
                        <input type="text"
                           ng-model="object.surfaceLocation.path"
                           name="surfaceLocationPath"
                           class="form-control"
                           id="urlDynamicSearch"
                           style="width:300px"
                           typeahead="string for string in config.recentPathList | filter:$viewValue | limitTo:10"/>
                    </td>
                    <td>
                        <!--<span class="errors" ng-show="form.surfaceLocationPath.$dirty && form.surfaceLocationPath.$error.url">URL is invalid.</span>-->
                    </td>
                </tr>
                <tr ng-show="object.group === 'static'">
                    <td>Source File</td>
                    <td style="padding:5px;" class="inputValue">
                        <input type="text"
                           ng-model="object.dataFlowElements[0].sourceFileName"
                           name="dataFlowElements[0].sourceFileName"
                           class="form-control"
                           id="urlStaticSearch"
                           typeahead="string for string in config.recentFileList | filter:$viewValue | limitTo:10"/>
                    </td>
                    <td>
                        <span class="errors" ng-show="object.sourceFileLocation_error">{{ object.sourceFileLocation_error }}</span>
                    </td>
                </tr>
                <tr ng-show="object.group === 'static'">
                    <td>Line Number</td>
                    <td class="inputValue">
                        <input type="number" style="width:350px;" name="dataFlowElements[0].lineNumber" id="lineNumberInput" name="lineNumber"
                               ng-model="object.dataFlowElements[0].lineNumber" size="50" maxlength="255"/>
                    </td>
                    <td>
                        <span class="errors" ng-show="form.lineNumber.$dirty && form.lineNumber.$error.number">Not valid number.</span>
                        <span class="errors" ng-show="object.dataFlowElements_error">{{ object.dataFlowElements_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td>Parameter</td>
                    <td class="inputValue">
                        <input type="text" style="width:350px;" id="parameterInput" name="surfaceLocation.parameter" ng-model="object.surfaceLocation.parameter" size="50" maxlength="127"/>
                    </td>
                    <td>
                        <span class="errors" ng-show="object.surfaceLocation_parameter_error">{{ object.surfaceLocation_parameter_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td>Severity</td>
                    <td class="inputValue">
                        <select style="width:350px;" id="severityInput" name="channelSeverity" ng-model="object.channelSeverity" ng-options="severity.displayName for severity in config.manualSeverities"/>
                    </td>
                    <td/>
                </tr>
                <tr>
                    <td>Description</td>
                    <td class="inputValue">
                        <textarea style="width:350px;" id="descriptionInput" name="longDescription" ng-model="object.longDescription" rows="5" cols="50" required></textarea>
                    </td>
                    <td>
                        <span class="errors" ng-show="form.longDescription.$dirty && form.longDescription.$error.required">Description is required.</span>
                        <span class="errors" ng-show="object.longDescription_error">{{ object.longDescription_error }}</span>
                    </td>
                </tr>
            </tbody>
        </table>
	</div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>

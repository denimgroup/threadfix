<script type="text/ng-template" id="editManualFindingForm.html">

	<div class="modal-header">
		<h4>Edit Finding</h4>
	</div>
    <div ng-form="form" class="modal-body" ng-init="object.group =  object.isStatic ? 'static' : 'dynamic'">
	<table class="modal-form-table">
		<tbody>
        <tr>
            <td>
                <input style="margin-right:5px" ng-model="object.group" id="dynamicRadioButton" type="radio" name="group" value="dynamic">Dynamic
            </td>
            <td>
                <input style="margin-right:5px" ng-model="object.group" id="staticRadioButton" type="radio" name="group" value="static">Static
            </td>
        </tr>
        <tr>
            <td style="padding:5px;">CWE</td>
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
            <td style="padding:5px;">URL</td>
            <td style="padding:5px;" class="inputValue">
                <input type="text"
                       ng-model="object.surfaceLocation.path"
                       name="surfaceLocationPath"
                       class="form-control"
                       id="urlInput"
                       style="width:300px"
                       typeahead="string for string in config.recentPathList | filter:$viewValue | limitTo:10"/>
            </td>
            <td>
                <!--<span class="errors" ng-show="form.surfaceLocationPath.$dirty && form.surfaceLocationPath.$error.url">URL is invalid.</span>-->
            </td>
        </tr>
        <tr ng-show="object.group === 'static'">
            <td style="padding:5px;">Source File</td>
            <td style="padding:5px;" class="inputValue">
                <input type="text"
                       ng-model="object.dataFlowElements[0].sourceFileName"
                       name="dataFlowElements[0].sourceFileName"
                       class="form-control"
                       id="sourceFileInput"
                       typeahead="string for string in config.recentFileList | filter:$viewValue | limitTo:10"/>
            </td>
        </tr>
        <tr ng-show="object.group === 'static'">
            <td style="padding:5px;">Line Number</td>
            <td class="inputValue">
                <input type="number" style="width:350px;" name="dataFlowElements[0].lineNumber" id="lineNumberInput" name="lineNumber"
                       ng-model="object.dataFlowElements[0].lineNumber" size="50" maxlength="255"/>
            </td>
            <td>
                <span class="errors" ng-show="form.lineNumber.$dirty && form.lineNumber.$error.number">Not valid number.</span>
                <span class="errors" ng-show="object.dataFlowElements_error">{{ object.dataFlowElements_error }}</span>
            </td>
        </tr>
        <tr ng-show="object.group === 'static'">
            <td>Line Text</td>
            <td class="inputValue">
                <input type="text" style="width:350px;" id="lineTextInput" name="lineText"
                       ng-model="object.dataFlowElements[0].lineText" size="50" maxlength="255"/>
            </td>
            <td>
            </td>
        </tr>
        <tr>
            <td style="padding:5px;">Parameter</td>
            <td class="inputValue">
                <input type="text" style="width:350px;" id="parameterInput" name="surfaceLocation.parameter" ng-model="object.surfaceLocation.parameter" size="50" maxlength="127"/>
            </td>
            <td>
                <span class="errors" ng-show="object.surfaceLocation_parameter_error">{{ object.surfaceLocation_parameter_error }}</span>
            </td>
        </tr>
        <tr>
            <td style="padding:5px;">Severity</td>
            <td class="inputValue">
                <select style="width:350px;" id="severityInput" name="channelSeverity" ng-model="object.channelSeverity" ng-options="severity.name for severity in config.manualSeverities"/>
            </td>
            <td/>
        </tr>
        <tr>
            <td style="padding:5px;">Description</td>
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

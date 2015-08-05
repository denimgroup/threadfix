<script type="text/ng-template" id="channelVulnerabilityFilterForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            {{ config.title }}

            <span ng-show="config.showDelete" class="delete-span">
				<a id="deleteButton"
                   ng-click="showDeleteDialog('filter')"
                   class="apiKeyDeleteButton btn btn-danger header-button"
                   type="submit">Delete</a>
			</span>

        </h4>
    </div>
    <div ng-form="form" ng-enter="ok(form.$valid)" class="modal-body">

        <table class="modal-form-table">
            <tr>
                <td>Source Scanner Type</td>
                <td>
                    <input id="sourceChannelType.name"
                           required style="z-index:4000;width:500px"
                           type="text"
                           name = "sourceChannelTypeName"
                           ng-model="object.sourceChannelType"
                           typeahead="channelType as channelType.name for channelType in config.channelTypes | filter:$viewValue | limitTo:10"
                           typeahead-on-select="object.sourceChannelVulnerability = undefined;"
                           class="form-control"/>
                    <span id="sourceChannelTypeRequiredError" class="errors" ng-show="form.sourceChannelTypeName.$dirty && form.sourceChannelTypeName.$error.required">Channel Type is required.</span>
                    <span id="sourceChannelTypeNameError" class="errors" ng-show="object.sourceChannelType_name_error"> {{ object.sourceChannelType_name_error }}</span>
                </td>
            </tr>
            <tr>
                <td>Source Scanner Vulnerability</td>
                <td>
                    <input id="sourceChannelVulnerability.name"
                           required style="z-index:4000;width:500px"
                           type="text"
                           name = "sourceChannelVulnerabilityName"
                           ng-model="object.sourceChannelVulnerability"
                           typeahead="vulnerability as vulnerability.name for vulnerability in config.channelVulnerabilitiesMap[object.sourceChannelType.name] | filter: {name: $viewValue} : startsWith | limitTo:10"
                           class="form-control"/>
                    <span id="sourceChannelVulnerabilityRequiredError" class="errors" ng-show="form.sourceChannelVulnerabilityName.$dirty && form.sourceChannelVulnerabilityName.$error.required">Scanner Vulnerability is required.</span>
                    <span id="sourceChannelVulnerabilityNameError" class="errors" ng-show="object.sourceChannelVulnerability_name_error"> {{ object.sourceChannelVulnerability_name_error }}</span>
                </td>
            </tr>
            <tr>
                <td>
                    Target Generic Severity Type
                </td>
                <td>
                    <select id="targetGenericSeverity.id" required style="width:320px" name="targetGenericSeverityId" ng-model="object.targetGenericSeverity.id">
                        <option ng-selected="severity.id === object.targetGenericSeverity.id" ng-repeat = "severity in config.genericSeverities" value="{{ severity.id }}"> {{ severity.displayName }} </option>
                    </select>
                    <span id="genericSeverityRequiredError" class="errors" ng-show="form.targetGenericSeverityId.$dirty && form.targetGenericSeverityId.$error.required">Generic Severity is required.</span>
                    <span id="genericSeverityIdError" class="errors" ng-show="object.targetGenericSeverity_id_error"> {{ object.targetGenericSeverity_id_error }}</span>
                </td>
            </tr>
        </table>
        <div style="height:300px"></div>

    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>

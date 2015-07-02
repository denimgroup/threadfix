<script type="text/ng-template" id="vulnerabilityFilterForm.html">
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
                <td>Source Vulnerability Type</td>
                <td>
                    <input id="sourceGenericVulnerability.name"
                           required style="z-index:4000;width:500px"
                           type="text"
                           name = "sourceGenericVulnerabilityName"
                           ng-model="object.sourceGenericVulnerability.name"
                           typeahead="(vulnerability.name + ' (CWE ' + vulnerability.displayId + ')') for vulnerability in config.genericVulnerabilities | filter:$viewValue | limitTo:10"
                           class="form-control"/>
                    <span id="genericVulnerabilityRequiredError" class="errors" ng-show="form.sourceGenericVulnerabilityName.$dirty && form.sourceGenericVulnerabilityName.$error.required">Vulnerability is required.</span>
                    <span id="genericVulnerabilityNameError" class="errors" ng-show="object.sourceGenericVulnerability_name_error"> {{ object.sourceGenericVulnerability_name_error }}</span>
                </td>
            </tr>
            <tr>
                <td>
                    Target Severity Type
                </td>
                <td>
                    <select id="targetGenericSeverity.id" required style="width:320px" name="targetGenericSeverityId" ng-model="object.targetGenericSeverity.id">
                        <option ng-selected="severity.id === object.targetGenericSeverity.id" ng-repeat = "severity in config.genericSeverities" value="{{ severity.id }}"> {{ severity.displayName }} </option>
                    </select>
                    <span id="genericSeverityRequiredError" class="errors" ng-show="form.targetGenericSeverityId.$dirty && form.targetGenericSeverityId.$error.required">Severity is required.</span>
                    <span id="genericSeverityIdError" class="errors" ng-show="object.targetGenericSeverity_id_error"> {{ object.targetGenericSeverity_id_error }}</span>
                </td>
            </tr>
        </table>
        <div style="height:300px"></div>

    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>

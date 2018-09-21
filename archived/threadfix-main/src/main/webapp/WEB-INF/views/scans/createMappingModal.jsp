<script type="text/ng-template" id="createMappingModal.html">
    <div class="modal-header">
        <h4>Create Mapping</h4>
    </div>
    <div ng-form="form" class="modal-body">
        <table class="modal-form-table">
            <tbody>
                <tr>
                    <td>Scanner Name</td>
                    <td>{{ object.channelName }}</td>
                </tr>
                <tr>
                    <td>Scanner Type</td>
                    <td>{{ object.channelVulnerabilityCode }}</td>
                </tr>
                <tr>
                    <td>CWE</td>
                    <td class="typeaheadPointer">
                        <input id="sourceGenericVulnerability.name"
                               required style="z-index:1041;width:500px"
                               type = "text"
                               name = "sourceGenericVulnerabilityName"
                               ng-model="object.genericVulnerabilityId"
                               typeahead="vulnerability.displayId as (vulnerability.name + ' (CWE ' + vulnerability.displayId + ')') for vulnerability in config.genericVulnerabilities | filter:$viewValue | limitTo:10"
                               class="form-control"/>
                        <span id="genericVulnerabilityRequiredError" class="errors" ng-show="form.sourceGenericVulnerabilityName.$dirty && form.sourceGenericVulnerabilityName.$error.required">Vulnerability is required.</span>
                        <span id="genericVulnerabilityNameError" class="errors" ng-show="object.sourceGenericVulnerability_name_error"> {{ object.sourceGenericVulnerability_name_error }}</span>
                    </td>
                </tr>

            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>

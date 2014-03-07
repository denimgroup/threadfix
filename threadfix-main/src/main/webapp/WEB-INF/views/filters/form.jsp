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
                    <input required style="z-index:4000;width:320px"
                           type="text"
                           name = "sourceGenericVulnerability.name"
                           ng-model="object.sourceGenericVulnerability.name"
                           typeahead="(vulnerability.name + ' (CWE ' + vulnerability.id + ')') for vulnerability in config.genericVulnerabilities | filter:$viewValue | limitTo:10"
                           class="form-control"/>
                </td>
            </tr>
            <tr>
                <td>
                    Target Severity Type
                </td>
                <td>
                    <select required style="width:320px" name="targetGenericSeverity.id" ng-model="object.targetGenericSeverity.id">
                        <option ng-selected="severity.id === object.targetGenericSeverity.id" ng-repeat = "severity in config.genericSeverities" value="{{ severity.id }}"> {{ severity.name }} </option>
                    </select>
                </td>
            </tr>
        </table>
        <div style="height:300px"></div>

    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>

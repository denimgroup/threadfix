<script type="text/ng-template" id="editScanResultFilterModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            New Scan Result Filter
            <span class="delete-span">
                <a id="deleteButton" class="btn btn-danger header-button" type="submit" ng-click="showDeleteDialog('Scan Result Filter')">Delete</a>
            </span>
        </h4>
    </div>

    <div ng-form="form" class="modal-body">
        <table class="modal-form-table">
            <tbody class="modal-form-table">
            <tr>
                <td>Scanner Type</td>
                <td>
                    <select ng-model="object.channelType.id"
                            id="channelTypeSelect"
                            name="channelTypeId">
                        <option ng-selected="object.channelType.id === channelType.id" ng-repeat="channelType in config.channelTypes" value="{{channelType.id}}">{{channelType.name}}</option>
                    </select>
                </td>
                <td>
                        <span id="typeServerError" class="errors" ng-show="object.channelType_error">
                            {{ object.channelType_error }}
                        </span>
                </td>
            </tr>
            <tr>
                <td>Severity</td>
                <td>
                    <select ng-model="object.genericSeverity.id"
                            id="severitySelect"
                            name="severityId">
                        <option ng-selected="object.genericSeverity.id === severity.id" ng-repeat="severity in config.severities" value="{{severity.id}}">
                            {{severity.name}}
                        </option>
                    </select>
                </td>
                <td>
                        <span id="severityServerError" class="errors" ng-show="object.genericSeverity_error">
                            {{ object.genericSeverity_error }}
                        </span>
                </td>
            </tr>
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
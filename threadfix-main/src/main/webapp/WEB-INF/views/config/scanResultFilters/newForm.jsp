<script type="text/ng-template" id="newScanResultFilterModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            New Scan Result Filter
        </h4>
    </div>

    <div ng-form="form" class="modal-body">
        <table class="modal-form-table">
            <tbody class="modal-form-table">
                <tr>
                    <td>Scanner Type</td>
                    <td>
                        <select ng-options="channelType.name for channelType in config.channelTypes"
                                ng-model="object.channelType"
                                id="channelTypeSelect"
                                name="channelTypeId">
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
                        <select ng-options="severity.name for severity in config.severities"
                                ng-model="object.genericSeverity"
                                id="severitySelect"
                                name="severityId">
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
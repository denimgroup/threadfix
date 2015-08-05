<div ng-form="form" class="modal-body" style="padding-bottom: 65px">
    <table class="modal-form-table">
        <tr>
            <td>Teams concerned</td>
            <td>
                <multi-select
                        id-prefix="tags"
                        input-model="config.organizations"
                        output-model="object.organizations"
                        button-label="name"
                        item-label="name"
                        tick-property="selected"
                        >
                </multi-select>
                <span class="errors" ng-show="object.organizations_error"> {{ object.organizations_error }}</span>
            </td>
        </tr>
        <tr>
            <td>Severity threshold</td>
            <td>
                <select ng-options="genericSeverity.id as genericSeverity.displayName for genericSeverity in config.genericSeverities" ng-model="object.severityLevel.id" required/></select>
                <span class="errors" ng-show="object.severityLevel_error"> {{ object.severityLevel_error }}</span>
            </td>
        </tr>
        <%@ include file="/WEB-INF/views/applications/forms/addScheduledJobFields.jsp" %>
    </table>
</div>

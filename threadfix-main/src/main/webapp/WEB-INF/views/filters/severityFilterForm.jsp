

<div id="severitySuccessMessage" ng-show="severitySuccessMessage" class="alert alert-success">
    <button class="close" ng-click="severitySuccessMessage = undefined" type="button">&times;</button>
    {{ severitySuccessMessage }}
</div>
<div ng-show="severityErrorMessage" class="alert alert-danger">
    <button class="close" ng-click="severityErrorMessage = undefined" type="button">&times;</button>
    <span id="severityErrorMessage">{{ severityErrorMessage }}</span>
</div>

<div ng-form="form" class="modal-body">
    <table class="table noBorders">
        <tbody>
            <tr>
                <td style="width:130px">Enable Severity Filters</td>
                <td>
                    <input type="checkbox" ng-model="severityFilter.enabled" id="enabledBox" name="disabled">
                </td>
                <td><form:errors name="enabled" cssClass="errors" /></td>
            </tr>
        </tbody>
    </table>
    <table class="table noBorders">
        <thead>
            <tr>
                <th style="width:80px;">Severity</th>
                <th style="width:30px"></th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>Critical</td>
                <td>
                    <div class="btn-group">
                        <label class="btn" ng-model="severityFilter.showCritical" ng-class="{ disabled : !severityFilter.enabled }" ng-click="setSeverity('showCritical', true)" btn-radio="true">Show</label>
                        <label class="btn" ng-model="severityFilter.showCritical" ng-class="{ disabled : !severityFilter.enabled }" ng-click="setSeverity('showCritical', false)" btn-radio="false">Hide</label>
                    </div>
                </td>
            </tr>
            <tr>
                <td>High</td>
                <td>
                    <div class="btn-group">
                        <label class="btn" ng-model="severityFilter.showHigh" ng-class="{ disabled : !severityFilter.enabled }" ng-click="setSeverity('showHigh', true)" btn-radio="true">Show</label>
                        <label class="btn" ng-model="severityFilter.showHigh" ng-class="{ disabled : !severityFilter.enabled }" ng-click="setSeverity('showHigh', false)" btn-radio="false">Hide</label>
                    </div>
                </td>
            </tr>
            <tr>
                <td>Medium</td>
                <td>
                    <div class="btn-group">
                        <label class="btn" ng-model="severityFilter.showMedium" ng-class="{ disabled : !severityFilter.enabled }" ng-click="setSeverity('showMedium', true)" btn-radio="true">Show</label>
                        <label class="btn" ng-model="severityFilter.showMedium" ng-class="{ disabled : !severityFilter.enabled }" ng-click="setSeverity('showMedium', false)" btn-radio="false">Hide</label>
                    </div>
                </td>
            </tr>
            <tr>
                <td>Low</td>
                <td>
                    <div class="btn-group">
                        <label class="btn" ng-model="severityFilter.showLow" ng-class="{ disabled : !severityFilter.enabled }" ng-click="setSeverity('showLow', true)" btn-radio="true">Show</label>
                        <label class="btn" ng-model="severityFilter.showLow" ng-class="{ disabled : !severityFilter.enabled }" ng-click="setSeverity('showLow', false)" btn-radio="false">Hide</label>
                    </div>
                </td>
            </tr>
            <tr>
                <td>Info</td>
                <td>
                    <div class="btn-group">
                        <label class="btn" ng-model="severityFilter.showInfo" ng-class="{ disabled : !severityFilter.enabled }" ng-click="setSeverity('showInfo', true)" btn-radio="true">Show</label>
                        <label class="btn" ng-model="severityFilter.showInfo" ng-class="{ disabled : !severityFilter.enabled }" ng-click="setSeverity('showInfo', false)" btn-radio="false">Hide</label>
                    </div>
                </td>
            </tr>
        </tbody>
    </table>
</div>
<a ng-hide="submittingSeverityFilter" id="submitSeverityFilterForm"
        class="modalSubmit btn btn-primary"
        ng-click="submitSeverityFilterForm()">
    Save Severity Filter Changes
</a>
<a ng-show="submittingSeverityFilter"
        class="modalSubmit btn btn-primary"
        ng-click="submitSeverityFilterForm()">
    <span class="spinner"></span>
    Saving
</a>
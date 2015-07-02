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
                <th style="width:30px">Show</th>
                <th style="width:30px">Hide</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td generic-severity="Critical"></td>
                <td class="centered">
                    <input id="showCritical1" type="radio" ng-model="severityFilter.showCritical" ng-disabled="!severityFilter.enabled" name="showCritical" value="true"/>
                </td>
                <td class="centered">
                    <input id="showCritical2" type="radio" ng-model="severityFilter.showCritical" ng-disabled="!severityFilter.enabled" name="showCritical" value="false"/>
                </td>
            </tr>
            <tr>
                <td generic-severity="High"></td>
                <td class="centered">
                    <input id="showHigh1" type="radio" ng-model="severityFilter.showHigh" ng-disabled="!severityFilter.enabled" name="showHigh" value="true"/>
                </td>
                <td class="centered">
                    <input id="showHigh2" type="radio" ng-model="severityFilter.showHigh" ng-disabled="!severityFilter.enabled" name="showHigh" value="false"/>
                </td>
            </tr>
            <tr>
                <td generic-severity="Medium"></td>
                <td class="centered">
                    <input id="showMedium1" type="radio" ng-model="severityFilter.showMedium" ng-disabled="!severityFilter.enabled" name="showMedium" value="true"/>
                </td>
                <td class="centered">
                    <input id="showMedium2" type="radio" ng-model="severityFilter.showMedium" ng-disabled="!severityFilter.enabled" name="showMedium" value="false"/>
                </td>
            </tr>
            <tr>
                <td generic-severity="Low"></td>
                <td class="centered">
                    <input id="showLow1" type="radio" ng-model="severityFilter.showLow" ng-disabled="!severityFilter.enabled" name="showLow" value="true"/>
                </td>
                <td class="centered">
                    <input id="showLow2" type="radio" ng-model="severityFilter.showLow" ng-disabled="!severityFilter.enabled" name="showLow" value="false"/>
                </td>
            </tr>
            <tr>
                <td generic-severity="Info"></td>
                <td class="centered">
                    <input id="showInfo1" type="radio" ng-model="severityFilter.showInfo" ng-disabled="!severityFilter.enabled" name="showInfo" value="true"/>
                </td>
                <td class="centered">
                    <input id="showInfo2" type="radio" ng-model="severityFilter.showInfo"  ng-disabled="!severityFilter.enabled" name="showInfo" value="false"/>
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

<div ng-form="form" class="modal-body">

    <table class="table noBorders">
        <tbody>
            <tr>
                <td style="width:130px">Enable Severity Filters</td>
                <td>
                    <input type="checkbox" ng-model="enabled" id="enabledBox" name="enabled">
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
                <td>Critical</td>
                <td class="centered">
                    <input type="radio" class="needsEnabled" name="showCritical" value="true"/>
                </td>
                <td class="centered">
                    <input type="radio" class="needsEnabled" name="showCritical" value="false"/>
                </td>
            </tr>
            <tr>
                <td>High</td>
                <td class="centered">
                    <input type="radio" class="needsEnabled" name="showHigh" value="true"/>
                </td>
                <td class="centered">
                    <input type="radio" class="needsEnabled" name="showHigh" value="false"/>
                </td>
            </tr>
            <tr>
                <td>Medium</td>
                <td class="centered">
                    <input type="radio" class="needsEnabled" name="showMedium" value="true"/>
                </td>
                <td class="centered">
                    <input type="radio" class="needsEnabled" name="showMedium" value="false"/>
                </td>
            </tr>
            <tr>
                <td>Low</td>
                <td class="centered">
                    <input type="radio" class="needsEnabled" name="showLow" value="true"/>
                </td>
                <td class="centered">
                    <input type="radio" class="needsEnabled" name="showLow" value="false"/>
                </td>
            </tr>
            <tr>
                <td>Info</td>
                <td class="centered">
                    <input type="radio" class="needsEnabled" name="showInfo" value="true"/>
                </td>
                <td class="centered">
                    <input type="radio" class="needsEnabled" name="showInfo" value="false"/>
                </td>
            </tr>
        </tbody>
    </table>
</div>
<a id="submitSeverityFilterForm"
        class="modalSubmit btn btn-primary"
        data-success-div="tabsDiv"
        data-form-div="severityFilterFormDiv"
        >
    Save Severity Filter Changes
</a>
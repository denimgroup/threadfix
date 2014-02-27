<script type="text/ng-template" id="addDefectTrackerModal.html">

    <div class="modal-header">
        <h4 id="myModalLabel">Add Defect Tracker</h4>
        <div class="left-align" id="toReplaceDT"></div>
    </div>
    <div ng-form="form" id="addDefectTrackerDivInForm" class="modal-body">
        <table class="modal-form-table">
            <tr class="left-align">
                <td>Defect Tracker</td>
                <td class="inputValue">
                    <select ng-model="object.defectTrackerId" id="defectTrackerTypeSelect" name="defectTrackerType.id">
                        <option ng-repeat="tracker in config.defectTrackerList"
                                ng-selected="object.defectTracker.id === tracker.id"
                                value="{{ tracker.id }}">
                            {{ tracker.name }}
                        </option>
                    </select>
                </td>
                <td>
                    <button ng-click="switchTo('createDefectTracker')" class="btn">
                        Create Defect Tracker
                    </button>
                </td>
                <td colspan="2" >
                    <errors name="defectTracker.id" cssClass="errors" />
                </td>
            </tr>
            <tr class="left-align">
                <td>Username</td>
                <td class="inputValue">
                    <input type="text" ng-model="object.userName" style="margin:5px;" id="username" name="userName" size="50" maxlength="50"/>
                </td>
                <td colspan="2" >
                    <errors name="userName" cssClass="errors" />
                </td>
            </tr>
            <tr class="left-align">
                <td>Password</td>
                <td class="inputValue">
                    <input type="password" ng-model="object.password" style="margin:5px;" id="password" showPassword="true" name="password" size="50" maxlength="50"/>
                </td>
                <td colspan="2" >
                    <errors name="password" cssClass="errors" />
                </td>
            </tr>
            <tr>
            <tr ng-show="productNames" class="left-align">
                <td id="projectname">Product Name</td>
                <td class="inputValue">
                    <select ng-model="object.projectName" id="productNameSelect" name="productName">
                        <option ng-repeat="name in productNames"
                                ng-selected="object.projectName === name"
                                value="{{ name }}">
                            {{ name }}
                        </option>
                    </select>
                </td>
            </tr>
        </table>
    </div>
    <div class="modal-footer">
        <span class="errors" style="float:left">{{ error }}</span>

        <a class="btn" ng-click="cancel()">Close</a>
        <button id="loadingButton"
                disabled="disabled"
                class="btn btn-primary"
                ng-show="loading">
            <span class="spinner"></span>
            Submitting
        </button>
        <button id="submit"
                ng-class="{ disabled : form.$invalid }"
                class="btn btn-primary"
                ng-mouseenter="form.name.$dirty = true"
                ng-hide="loading || !productNames"
                ng-click="ok(form.$valid)">Add Defect Tracker</button>
        <button id="submit"
                ng-class="{ disabled : form.$invalid }"
                class="btn btn-primary"
                ng-mouseenter="form.name.$dirty = true"
                ng-hide="productNames"
                ng-click="getProductNames()">Get Product Names</button>
    </div>
</script>
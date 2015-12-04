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
                    <select ng-model="object.defectTrackerId" id="defectTrackerId" name="defectTrackerTypeId" ng-change="updateDefaultCredentialsAndProduct()">
                        <option ng-repeat="tracker in config.defectTrackerList"
                                ng-selected="object.defectTracker.id === tracker.id"
                                value="{{ tracker.id }}">
                            {{ tracker.name }}
                        </option>
                    </select>
                </td>
                <td>
                    <button id="createDefectTrackerButton" ng-click="switchTo('createDefectTracker')" class="btn">
                        Create Defect Tracker
                    </button>
                </td>
                <td colspan="2" >
                    <errors name="defectTracker.id" cssClass="errors" />
                    <span class="errors" ng-show="object.defectTracker_id_error"> {{ object.defectTracker_id_error }}</span>
                </td>
            </tr>
            <tr class="left-align">
                <td>Use Default Credentials</td>
                <td class="inputValue">
                    <input type="checkbox" ng-model="object.useDefaultCredentials" id="useDefaultCredentials" ng-change="toggleUseDefaultCredentials()">
                </td>
            </tr>
            <tr class="left-align">
                <td>Username</td>
                <td class="inputValue">
                    <input type="text" ng-model="object.userName" id="username" name="userName" size="50" maxlength="50" ng-disabled="object.useDefaultCredentials"/>
                </td>
                <td colspan="2" >
                    <errors name="userName" cssClass="errors" />
                    <span class="errors" ng-show="object.userName_error"> {{ object.userName_error }}</span>
                </td>
            </tr>
            <tr class="left-align">
                <td>Password</td>
                <td class="inputValue">
                    <input type="password" ng-model="object.password" id="password" showPassword="true" name="password" size="50" maxlength="50" ng-disabled="object.useDefaultCredentials"/>
                </td>
                <td colspan="2" >
                    <errors name="password" cssClass="errors" />
                    <span class="errors" ng-show="form.password.$dirty && form.password.$error.maxlength">Maximum length is 50.</span>
                    <span class="errors" ng-show="object.password_error"> {{ object.password_error }}</span>
                </td>
            </tr>
            <tr class="left-align">
                <td>Use Default Product</td>
                <td class="inputValue">
                    <input type="checkbox" ng-model="object.useDefaultProduct" id="useDefaultProduct" ng-change="toggleUseDefaultProduct()">
                </td>
            </tr>
            <tr ng-show="productNames" class="left-align" id="productNamesSection">
                <td id="projectname">Product Name</td>
                <td class="inputValue">

                    <input-dropdown
                            id="productNameSelect"
                            input-placeholder="Enter Product"
                            input-name="productName"
                            selected-item="object.projectName"
                            input-value-init="object.projectName"
                            default-dropdown-items="productNames"
                            filter-list-method="filterStringList(userInput)"
                            input-required = "true"
                    >
                    </input-dropdown>

                </td>
                <td colspan="2" >
                    <errors name="productName" cssClass="errors" />
                    <span class="errors" ng-show="object.projectName_error"> {{ object.projectName_error }}</span>
                </td>
            </tr>
        </table>
        <div style="height:100px"></div>
    </div>
    <div class="modal-footer">
        <span class="errors" style="float:left">{{ error }}</span>

        <a class="btn" id="closeModalButton" ng-click="cancel()">Close</a>
        <button id="loadingButton"
                disabled="disabled"
                class="btn btn-primary"
                ng-show="loading && productNames">
            <span class="spinner"></span>
            Submitting
        </button>
        <button id="submit"
                ng-class="{ disabled : form.$invalid }"
                class="btn btn-primary"
                ng-mouseenter="form.name.$dirty = true"
                ng-hide="loading || !productNames"
                ng-click="ok(form.$valid)">Add Defect Tracker</button>

        <button id="loadingProductNamesButton"
                disabled="disabled"
                class="btn btn-primary"
                ng-show="loading && !productNames">
            <span class="spinner"></span>
            Loading Product Names
        </button>
        <button id="getProductNames"
                ng-class="{ disabled : form.$invalid }"
                class="btn btn-primary"
                ng-mouseenter="form.name.$dirty = true"
                ng-hide="loading || productNames"
                ng-click="getProductNames()">Get Product Names</button>
    </div>
</script>
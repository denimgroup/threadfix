<script type="text/ng-template" id="editTrackerModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            Edit Defect Tracker
            <span class="delete-span">
                <a id="deleteButton" class="btn btn-danger header-button" type="submit" ng-click="showDeleteDialog('Defect Tracker')">Delete</a>
            </span>
        </h4>
    </div>
    <div ng-form="form" class="modal-body">
        <table class="modal-form-table">
            <tbody>
                <tr>
                    <td>Name</td>
                    <td>
                        <input id="nameInput"
                               name="name"
                               type="text"
                               focus-on="focusInput"
                               size="50"
                               ng-maxlength="50"
                               ng-model="object.name" required/>
                    </td>
                    <td>
                        <span id="nameRequiredError" class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                        <span id="nameCharacterLimitError" class="errors" ng-show="form.name.$dirty && form.name.$error.maxlength">Over 50 characters limit!</span>
                        <span id="nameServerError" class="errors" ng-show="object.name_error"> {{ object.name_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td class="no-color">URL</td>
                    <td class="no-color inputValue">
                        <input id="urlInput"
                               type="url"
                               name="url"
                               size="50"
                               ng-model="object.url"
                               maxlength="255"
                               value="${ defectTracker.url }" required/>
                    </td>
                    <td>
                        <span id="urlRequiredError" class="errors" ng-show="form.url.$dirty && form.url.$error.required">URL is required.</span>
                        <span id="urlInvalidError" class="errors" ng-show="form.url.$dirty && form.url.$error.url">URL is invalid.</span>
                        <span id="urlCharacterLimitError" class="errors" ng-show="form.url.$dirty && form.url.$error.maxlength">Over 255 characters limit!</span>
                        <span id="urlServerError" class="errors" ng-show="object.url_error"> {{ object.url_error }}</span>
                        <span id="urlSelfSignedCertificateError" class="errors" ng-show="showKeytoolLink">Instructions for importing a self-signed certificate can be found <a target="_blank" href="https://github.com/denimgroup/threadfix/wiki/Importing-Self-Signed-Certificates">here</a>.</span>
                    </td>
                </tr>
                <tr>
                    <td class="no-color">Type</td>
                    <td class="no-color inputValue">
                        <select id="defectTrackerTypeSelect"
                                ng-model="object.defectTrackerType.id"
                                name="defectTrackerType.id">
                            <option ng-selected="object.defectTrackerType.id === type.id" ng-repeat="type in config.trackerTypes" value="{{ type.id }}">
                                {{ type.name }}
                            </option>
                        </select>
                    </td>
                    <td>
                        <span id="typeServerError" class="errors" ng-show="object.defectTrackerType_id_error"> {{ object.defectTrackerType_id_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td>Default Username</td>
                    <td class="inputValue">
                        <input type="text" focus-on="focusInput" ng-model="object.defaultUsername" id="defaultUsername" name="defaultUsername" size="50" maxlength="50"/>
                    </td>
                    <td colspan="2" >
                        <span class="errors" ng-show="object.defaultUsername_error"> {{ object.defaultUsername_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td>Default Password</td>
                    <td class="inputValue">
                        <input type="password" focus-on="focusInput" ng-model="object.defaultPassword" id="defaultPassword" name="defaultPassword" size="50" maxlength="50"/>
                    </td>
                    <td colspan="2" >
                        <span class="errors" ng-show="form.defaultPassword.$dirty && form.defaultPassword.$error.maxlength">Maximum length is 50.</span>
                        <span class="errors" ng-show="object.defaultPassword"> {{ object.defaultPassword_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td>
                        <button id="loadingProductNamesButton"
                                disabled="disabled"
                                class="btn btn-primary"
                                ng-show="loadingProductNames">
                            <span class="spinner"></span>
                            Loading Product Names
                        </button>
                        <button id="getProductNames"
                                class="btn btn-primary"
                                ng-hide="loadingProductNames"
                                ng-disabled="!(object.url && object.defaultPassword && object.defaultUsername)"
                                ng-click="getProductNames()">Get Product Names</button>
                    </td>
                </tr>
                <tr ng-show="productNames || object.defaultProductName" class="left-align">
                    <td id="projectname">Product Name</td>
                    <td class="inputValue">
                        <select ng-model="object.defaultProductName" id="productNameSelect" name="productName">
                            <option ng-repeat="name in productNames"
                                    ng-selected="object.defaultProductName === name"
                                    value="{{ name }}">
                                {{ name }}
                            </option>
                        </select>
                    </td>
                    <td colspan="2" >
                        <errors name="productName" cssClass="errors" />
                        <span class="errors" ng-show="object.defaultProductName_error"> {{ object.defaultProductName_error }}</span>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>

</script>
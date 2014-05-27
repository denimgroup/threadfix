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
                        <span id="urlSelfSignedCertificateError" class="errors" ng-show="showKeytoolLink">Instructions for importing a self-signed certificate can be found <a target="_blank" href="http://code.google.com/p/threadfix/wiki/ImportingSelfSignedCertificates">here</a>.</span>
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
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>

</script>
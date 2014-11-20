<script type="text/ng-template" id="newGRCToolModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">New GRC Tool</h4>
    </div>
    <div ng-form="form" class="modal-body">
        <table class="modal-form-table">
            <tbody>
                <tr>
                    <td>Type</td>
                    <td>
                        <select ng-options="type.name for type in config.toolTypes" ng-model="object.grcToolType" id="grcToolTypeSelect" name="grcToolTypeid" required></select>
                    </td>
                    <td>
                        <span id="typeServerError" class="errors" ng-show="object.grcToolType_id_error"> {{ object.grcToolType_id_error }}</span>
                        <span id="typeRequiredError" class="errors" ng-show="form.grcToolType.$dirty && form.grcToolType.$error.required">GRC Type is required.</span>
                    </td>
                </tr>
                <tr>
                    <td>Name</td>
                    <td class="inputValue">
                        <input type="text" focus-on="focusInput" ng-model="object.name" id="nameInput" name="name" size="50" maxlength="50" required/>
                    </td>
                    <td>
                        <span id="nameRequiredError" class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                        <span id="nameCharacterLimitError" class="errors" ng-show="form.name.$dirty && form.name.$error.maxlength">Over 50 characters limit!</span>
                        <span id="nameServerError" class="errors" ng-show="object.name_error"> {{ object.name_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td>URL</td>
                    <td class="no-color inputValue">
                        <input required type="url" ng-model="object.url" id="urlInput" name="url" size="50" ng-maxlength="255" value="http://"/>
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
                    <td>Username</td>
                    <td class="inputValue">
                        <input type="text" focus-on="focusInput" ng-model="object.username" id="usernameInput" name="username" size="60" maxlength="60" required/>
                    </td>
                    <td>
                        <span id="usernameRequiredError" class="errors" ng-show="form.username.$dirty && form.username.$error.required">Username is required.</span>
                        <span id="usernameCharacterLimitError" class="errors" ng-show="form.username.$dirty && form.username.$error.maxlength">Over 60 characters limit!</span>
                        <span id="usernameServerError" class="errors" ng-show="object.username_error"> {{ object.username_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td>Password</td>
                    <td class="inputValue">
                        <input type="password" focus-on="focusInput" ng-model="object.password" id="passwordInput" name="password" size="60" maxlength="60" required/>
                    </td>
                    <td>
                        <span id="passwordRequiredError" class="errors" ng-show="form.password.$dirty && form.password.$error.required">Password is required.</span>
                        <span id="passwordCharacterLimitError" class="errors" ng-show="form.password.$dirty && form.password.$error.maxlength">Over 60 characters limit!</span>
                        <span id="passwordServerError" class="errors" ng-show="object.password_error"> {{ object.password_error }}</span>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
<script type="text/ng-template" id="createDefaultProfileModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">New Defect Profile</h4>
    </div>
    <div ng-form="form" class="modal-body">
        <table class="modal-form-table">
            <tbody>
                <tr>
                    <td>Name</td>
                    <td class="inputValue">
                        <input type="text" focus-on="focusInput" ng-model="object.name" id="nameInput" name="name" size="50" maxlength="50" required/>
                    </td>
                    <td>
                        <span id="nameRequiredError" class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                        <span id="nameCharacterLimitError" class="errors" ng-show="form.name.$dirty && form.name.$error.maxlength">Over 50 characters limit!</span>
                        <span id="defaultNameInputNameError" class="errors" ng-show="object.name_error"> {{ object.name_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td>Reference Application</td>
                    <td>
                        <select ng-options="application.id as (application.team.name + ' / ' + application.name) for application in config.referenceApplications"
                                ng-model="object.referenceApplication.id"
                                id="referenceApplicationSelect"
                                name="defectTrackerTypeid">
                        </select>
                    </td>
                    <td>
                        <span id="referenceApplicationSelectError" class="errors" ng-show="object.referenceApplication.id_error">{{object.referenceApplication.id_error}}</span>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
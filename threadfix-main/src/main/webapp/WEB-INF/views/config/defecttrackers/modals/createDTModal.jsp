<script type="text/ng-template" id="newTrackerModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">New Defect Tracker</h4>
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
                        <span class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                        <span class="errors" ng-show="form.name.$dirty && form.name.$error.maxlength">Over 50 characters limit!</span>
                        <span class="errors" ng-show="object.nameError"> {{ object.nameError }}</span>
                    </td>
                </tr>
                <tr>
                    <td>URL</td>
                    <td class="no-color inputValue">
                        <input required type="url" ng-model="object.url" id="urlInput" name="url" size="50" ng-maxlength="255" value="http://"/>
                    </td>
                    <td>
                        <span class="errors" ng-show="form.url.$dirty && form.url.$error.required">URL is required.</span>
                        <span class="errors" ng-show="form.url.$dirty && form.url.$error.url">URL is invalid.</span>
                        <span class="errors" ng-show="form.url.$dirty && form.url.$error.maxlength">Over 255 characters limit!</span>
                        <span class="errors" ng-show="object.urlError"> {{ object.urlError }}</span>
                        <span class="errors" ng-show="showKeytoolLink">Instructions for importing a self-signed certificate can be found <a target="_blank" href="http://code.google.com/p/threadfix/wiki/ImportingSelfSignedCertificates">here</a>.</span>
                    </td>
                </tr>
                <tr>
                    <td>Type</td>
                    <td>
                        <select ng-options="type.name for type in config.trackerTypes"
                                ng-model="object.defectTrackerType"
                                id="defectTrackerTypeSelect"
                                name="defectTrackerTypeid">
                        </select>
                    </td>
                    <td>
                        <span class="errors" ng-show="object.defectTrackerTypeidError"> {{ object.defectTrackerTypeidError }}</span>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
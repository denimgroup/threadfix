<script type="text/ng-template" id="editTrackerModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            Edit Defect Tracker
            <span class="delete-span">
                <a id="deleteButton${ status.count }" class="btn btn-danger header-button" type="submit" ng-click="showDeleteDialog('Defect Tracker')">Delete</a>
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
                    <td ng-show="form.name.$dirty && form.name.$invalid">
                        <span class="errors" ng-show="form.name.$error.required">Name is required.</span>
                        <span class="errors" ng-show="form.name.$error.maxlength">Over 50 characters limit!</span>
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
                        <span class="errors" ng-show="form.url.$dirty && form.url.$error.required">URL is required.</span>
                        <span class="errors" ng-show="form.url.$dirty && form.url.$error.url">URL is invalid.</span>
                        <span class="errors" ng-show="form.url.$dirty && form.url.$error.maxlength">Over 255 characters limit!</span>
                        <!--<span ng-show="keytoolError" class="errors">Instructions for importing a self-signed certificate can be found <a target="_blank" href="http://code.google.com/p/threadfix/wiki/ImportingSelfSignedCertificates">here</a>.</span>-->
                    </td>
                    <!-- TODO put this back in -->
                    <!--<td class="no-color">-->
                        <!--<errors path="url" cssClass="errors" />-->
                        <!--<c:if test="${ showKeytoolLink }">-->
                            <!--<span class="errors">-->
                                <!--Instructions for importing a self-signed certificate can be found-->
                            <!--</span>-->
                            <!--<a target="_blank"-->
                               <!--href="http://code.google.com/p/threadfix/wiki/ImportingSelfSignedCertificates">-->
                                <!--here-->
                            <!--</a>.-->
                        <!--</c:if>-->
                    <!--</td>-->
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
                </tr>
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>

</script>
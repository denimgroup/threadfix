<script type="text/ng-template" id="newScanAgentTask.html">
    <div class="modal-header">
        <h4 id="myModalLabel">Add Scan Agent Task to Queue</h4>
    </div>
    <div class="modal-body" ng-form="form">
        <div id="scanQueueError" ng-show="scanQueueError" class="alert alert-error">
            {{ scanQueueError }}
        </div>
        <table class="modal-form-table">
            <tbody>
                <tr class="left-align">
                    <td>Scan</td>
                    <td>
                        <select style="width:300px;" name="scanQueueType" id="scan" ng-model="object.scanner">
                            <option ng-selected = "scanner === object.scanner"
                                    ng-repeat='scanner in config.scanners' value="{{ scanner }}"> {{ scanner }} </option>
                        </select>
                    </td>
                </tr>
                <tr class="left-align">
                    <td>Target URL</td>
                    <td>
                        <input style="width:300px;" id="urlInput" type='url' name='targetUrl' ng-model="object.targetUrl" ng-maxlength="255"/>
                    </td>
                    <td>
                        <span id="urlInputLengthError" class="errors" ng-show="form.targetUrl.$dirty && form.targetUrl.$error.maxlength">Maximum length is 255.</span>
                        <span id="urlInputInvalidUrlError" class="errors" ng-show="form.targetUrl.$dirty && form.targetUrl.$error.url">URL is invalid.</span>
                        <span id="urlInputError" class="errors" ng-show="object.targetUrl_error"> {{ object.name_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td>Scan Config</td>
                    <td>
                        <input id="defectId"
                               style="z-index:4000;width:300px"
                               type="text"
                               name = "id"
                               ng-model="object.scanConfig"
                               typeahead="document as (document.name + '.' + document.type) for document in config.documents | filter:$viewValue | limitTo:10"
                               typeahead-editable="true"
                               placeholder="Type file name"
                               class="form-control"/>
                        <a id="uploadDocQueueScanModalLink${ application.id }" class="btn" ng-click="switchTo('addDocInQueueScanModal')">Upload File</a>
                    </td>
                </tr>
            </tbody>
        </table>
        <div style="height:300px"></div>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
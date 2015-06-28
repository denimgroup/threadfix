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
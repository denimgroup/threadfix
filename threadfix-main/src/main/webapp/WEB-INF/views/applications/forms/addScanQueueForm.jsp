<script type="text/ng-template" id="newScanAgentTask.html">
    <div class="modal-header">
        <h4 id="myModalLabel">Add Scan Agent Task to Queue</h4>
    </div>
    <div class="modal-body" ng-form="form">
        <div id="scanQueueError" ng-show="scanQueueError" class="alert alert-error">
            {{ scanQueueError }}
        </div>
        Scanner:
        <select style="width:243px;" name="scanQueueType" id="scanner" ng-model="object.scanQueueType">
            <option ng-repeat='scanner in config.scanners' value="{{ scanner }}"> {{ scanner }} </option>
        </select>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
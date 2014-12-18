<script type="text/ng-template" id="submitGrcControlLoadingModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            Submit GRC {{ vulns.length === 1 ? 'Control' : 'Controls' }}
        </h4>
    </div>

    <div ng-form="form" class="modal-body">
        <%@ include file="../../vulnerabilities/littleVulnTable.jspf" %>
    </div>

    <div class="modal-footer">
        <span class="errors" style="float:left">{{ errorMessage }}</span>

        <a class="btn" ng-click="cancel()">Close</a>
        <button id="loadingButton"
                disabled="disabled"
                class="btn btn-primary"
                ng-show="loading">
            <span class="spinner"></span>
            Submitting
        </button>
        <button id="submit"
                ng-class="{ disabled : form.$invalid }"
                class="btn btn-primary"
                ng-mouseenter="form.summary.$dirty = true"
                ng-hide="loading"
                ng-click="ok(form)">Submit GRC {{ vulns.length === 1 ? 'Control' : 'Controls' }}</button>
    </div>
</script>

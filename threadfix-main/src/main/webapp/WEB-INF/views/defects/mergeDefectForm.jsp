<script type="text/ng-template" id="mergeDefectForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            Submit Defect
        </h4>
    </div>
	<div ng-form="form" class="modal-body">
        <div ng-hide="initialized" class="modal-spinner-div"><span class="spinner dark"></span>Loading</div><br>

        <table ng-show="initialized" class="dataTable">
            <tbody>
                <tr class="left-align">
                    <td style="padding:5px;">Select Defect</td>
                    <td style="padding:5px;">
                        <select style="margin-bottom:0;" ng-model="object.id" id="defectId" name="id" ng-options="defect for defect in config.defects" required>
                        </select>
                    </td>
                </tr>
            </tbody>
        </table>

        <%@ include file="littleVulnTable.jspf" %>
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
                ng-click="ok(form)">Submit Defect</button>
    </div>
</script>
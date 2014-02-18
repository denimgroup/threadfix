<script type="text/ng-template" id="newTeamModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            New Team
        </h4>
    </div>

    <form id="newTeamForm" name='form'>
        <div class="modal-body input-group">

            <table class="modal-form-table">
                <tr class="left-align">
                    <td>Name</td>
                    <td>
                        <input type='text' focus-on="open" name='name' ng-model="team.name" required/>
                        <span class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                    </td>
                </tr>
            </table>

        </div>
        <div class="modal-footer">
            <span style="float:left">{{ error }}</span>

            <button class="btn" ng-click="cancel()">Close</button>
            <button id="loadingButton"
                    disabled="disabled"
                    class="btn btn-primary"
                    ng-show="loading">
                <span class="spinner"></span>
                Submitting
            </button>
            <button id="addApplicationButton"
                    ng-class="{ disabled : form.$invalid }"
                    class="btn btn-primary"
                    ng-mouseenter="form.name.$dirty = true"
                    ng-hide="loading"
                    ng-click="ok(form.$valid)">Add Team</button>
        </div>
    </form>
</script>

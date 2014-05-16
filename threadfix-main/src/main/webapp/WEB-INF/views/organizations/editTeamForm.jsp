<script type="text/ng-template" id="editTeamModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            Edit Team
             <span class="delete-span">
                <a id="deleteTeamButton"
                   class="btn btn-danger header-button"
                   ng-click="showDeleteDialog('Team')">
                    Delete
                </a>
            </span>
        </h4>
    </div>

    <form id="newTeamForm" name='form'>
        <div class="modal-body input-group">
            <table class="modal-form-table">
                <tr class="left-align">
                    <td>Name</td>
                    <td>
                        <input id="teamNameInput" focus-on="focusInput" type='text' name='name' ng-model="object.name" ng-maxlength="60" required/>
                        <span id="requiredError" class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                        <span id="lengthError" class="errors" ng-show="form.name.$dirty && form.name.$error.maxlength">Maximum length is 60.</span>
                    </td>
                </tr>
            </table>
        </div>

    </form>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>

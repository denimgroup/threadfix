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
                        <input id="nameInput" focus-on="focusInput" type='text' name='name' ng-model="object.name" ng-maxlength="60" required/>
                        <span id="requiredError" class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                        <span id="lengthError" class="errors" ng-show="form.name.$dirty && form.name.$error.maxlength">Maximum length is 60.</span>
                    </td>
                </tr>
            </table>

        </div>
        <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
    </form>
</script>

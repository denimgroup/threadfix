<script type="text/ng-template" id="newDateModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            {{config.label}}
            <span class="delete-span">
                <!-- TODO remove onclick handler in favor of angular -->
				<a class="btn btn-danger header-button" id="deleteLink" href="{{ deleteUrl }}"
                   ng-click="showDeleteDialog('date range')">
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

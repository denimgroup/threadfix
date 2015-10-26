<script type="text/ng-template" id="newVersionForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            {{config.title}}
            <span class="delete-span" ng-if="object.id">
				<a id="deleteButton"
                   ng-click="showDeleteDialog('Version')"
                   class="btn btn-danger header-button"
                   type="submit">Delete</a>
			</span>
        </h4>
    </div>

	<div ng-form="form" class="modal-body">
        <table class="modal-form-table">
            <thead>
            <tr>
                <th class="first medium"></th>
                <th class="long"></th>
            </tr>
            </thead>
            <tbody>
            <tr>
                <td>Name</td>
                <td class="inputValue">
                    <input id="name" name="name" ng-model="object.name" type="text"
                               focus-on="focusInput" size="70" ng-maxlength="50" required="true"/>
                </td>
                <td>
                    <span id="versionInputRequiredError" class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                    <span id="lengthLimitError" class="errors" ng-show="form.name.$dirty && form.name.$error.maxlength">Over 50 characters limit!</span>
                    <span id="versionInputNameError" class="errors" ng-show="object.name_error"> {{ object.name_error }}</span>
                </td>
            </tr>

            <tr>
                <td>Date</td>
                <td>
                    <input id="date" name="date" type="text" class="form-control" style="width:206px;margin-bottom:0" datepicker-popup="dd-MMM-yyyy" ng-model="object.date"
                           is-open="startDateOpened" min-date="minDate" date-disabled="disabled(date, mode)" close-text="Close"
                           required="true" />
                </td>
                <td>
                    <span id="dateInputRequiredError" class="errors" ng-show="form.date.$dirty && form.date.$error.required">Date is required.</span>
                    <span class="error" ng-show="form.date.$error.date">Not a valid date.</span>
                    <span id="versionInputDateError" class="errors" ng-show="object.date_error"> {{ object.date_error }}</span>
                </td>
            </tr>
            </tbody>
        </table>
        <div style="height:350px"></div>
	</div>

    <div class="modal-footer">
        <span id="errorSpan" class="errors" style="float:left">{{ error }}</span>

        <a id="closeModalButton" class="btn" ng-click="cancel()">Close</a>
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
                ng-mouseenter="form.name.$dirty = true"
                ng-hide="loading"
                ng-click="convertDateAndSubmit(form.$valid)">{{ buttonText }}</button>
    </div>

</script>
<script type="text/ng-template" id="newKeyModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            New API Key
        </h4>
    </div>

	<div ng-form="form" class="modal-body">
        <table class="modal-form-table">
            <thead>
            <tr>
                <th class="first medium"></th>
                <th class="long"></th>
                <th></th>
            </tr>
            </thead>
            <tbody>
            <tr>
                <td>Note (optional) </td>
                <td class="inputValue">
                <input id="modalNote" name="note" ng-model="object.note" type="text"
                               focus-on="focusInput" size="70" ng-maxlength="255" />
                    </td>
                    <td>
                        <span id="lengthLimitError" class="errors" ng-show="form.note.$dirty && form.note.$error.maxlength">Over 255 characters limit!</span>
                    </td>
                </tr>
                <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_USERS">
                    <tr>
                        <td>User </td>
                        <td class="inputValue">
                            <input id="userTypeahead"
                                   type="text"
                                   class="form-control"
                                   placeholder="Type user name"
                                   typeahead-editable="true"
                                   ng-model="object.username"
                                   typeahead="user.name for user in config.users | filter:$viewValue | limitTo:10"
                                   ng-disabled="config.edit"/>


                        </td>
                        <td>
                            <span id="userError" class="errors" ng-show="object.username_error"> {{ object.username_error }}</span>
                        </td>
                    </tr>
                </security:authorize>
                <tr ng-if="!object.username">
                    <td>Restricted?</td>
                    <td class="inputValue" colspan="2">
                        <input id="modalRestricted" type="checkbox" ng-model="object.isRestrictedKey" name="isRestrictedKey"/>
                    </td>
                    <td/>
                </tr>
                <tr ng-if="object.username">
                    <td colspan="3">
                        This user's roles will be used to authorize actions for this API Key.
                    </td>
                </tr>
            </tbody>
        </table>
        <div style="height:100px"></div>
	</div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
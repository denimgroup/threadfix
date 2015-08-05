<script type="text/ng-template" id="newKeyModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            New API Key
        </h4>
    </div>

	<div ng-form="form" class="modal-body">
        <table class="modal-form-table">
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
                <tr ng-if="!object.username">
                    <td>Restricted?</td>
                    <td class="inputValue">
                        <input id="modalRestricted" type="checkbox" ng-model="object.isRestrictedKey" name="isRestrictedKey"/>
                    </td>
                </tr>
                <tr ng-if="object.username">
                    <td colspan="2">
                        This user's roles will be used to authorize actions for this API Key.
                    </td>
                </tr>
            </tbody>
        </table>
	</div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
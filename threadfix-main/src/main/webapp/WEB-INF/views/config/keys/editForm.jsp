<script type="text/ng-template" id="editKeyModal.html">

    <div class="modal-header">
        <h4 id="myModalLabel">Edit Key
        
            <span class="delete-span">
                <spring:url value="/delete" var="keyDeleteUrl">
                    <spring:param name="keyId" value="${ key.id }" />
                </spring:url>
                <a id="deleteButton"
                        ng-click="showDeleteDialog(object)"
                        class="apiKeyDeleteButton btn btn-danger header-button"
                        type="submit">Delete</a>
            </span>
        </h4>
    </div>
	<div ng-form="form" class="modal-body">
		<table class="modal-form-table">
			<tbody>
				<tr>
					<td>Note (optional)</td>
					<td class="inputValue">
						<input
                            id="note"
                            ng-model="object.note"
							name="note"
                            focus-on="focusInput"
   							size="70"
                            type="text"
							maxlength="255"/>
					</td>
                    <td>
                        <span id="lengthLimitError" class="errors" ng-show="form.note.$dirty && form.note.$error.maxlength">Over 255 characters limit!</span>
                    </td>
				</tr>
				<tr>
					<td>Restricted?</td>
					<td class="inputValue">
						<input type="checkbox" id="restricted" ng-model="object.isRestrictedKey" name="isRestrictedKey"/>
					</td>
				</tr>
			</tbody>
		</table>
	</div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
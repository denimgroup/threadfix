<script type="text/ng-template" id="createTagModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">Create New Tag</h4>
    </div>
	<div ng-form="form" class="modal-body">
		<table class="modal-form-table">
			<tbody>
			    <tr>
					<td class="">Name</td>
					<td class="inputValue no-color">
						<input ng-model="object.name" type="text" focus-on="focusInput" id="tagCreateNameInput" name="name" required ng-maxlength="50"/>
                        <span id="nameRequiredError" class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                        <span id="characterLimitError" class="errors" ng-show="form.name.$dirty && form.name.$error.maxlength">Over 50 characters limit!</span>
                        <span id="otherNameError" class="errors" ng-show="object.name_error"> {{ object.name_error }}</span>
					</td>
				</tr>
			</tbody>
		</table>
	</div>
	<%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
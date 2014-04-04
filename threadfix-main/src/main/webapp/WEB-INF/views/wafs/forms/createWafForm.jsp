<script type="text/ng-template" id="createWafModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">Create New WAF</h4>
    </div>
	<div ng-form="form" class="modal-body">
		<table class="modal-form-table">
			<tbody>
			    <tr>
					<td class="">Name</td>
					<td class="inputValue no-color">
						<input ng-model="object.name" type="text" focus-on="focusInput" id="wafCreateNameInput" name="name" required ng-maxlength="50"/>
                        <span class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                        <span class="errors" ng-show="form.name.$dirty && form.name.$error.maxlength">Over 50 characters limit!</span>
					</td>
				</tr>
				<tr>
					<td>Type</td>
					<td class="inputValue no-color">
						<select ng-model="object.wafType.id" id="typeSelect" name="wafTypeId" required>
							<option ng-repeat="type in config.wafTypeList"
                                    ng-selected="object.wafType.id === type.id"
                                    value="{{ type.id }}">
                                {{ type.name }}
                            </option>
						</select>
                        <span class="errors" ng-show="form.wafTypeId.$dirty && form.wafTypeId.$error.required">Type is required.</span>
					</td>
				</tr>
			</tbody>
		</table>
	</div>
	<%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
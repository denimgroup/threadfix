<script type="text/ng-template" id="createWafModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">Create New WAF</h4>
    </div>
	<div ng-form="form" class="modal-body">
		<table class="dataTable">
			<tbody>
			    <tr>
					<td class="">Name</td>
					<td class="inputValue no-color">
						<input focus-on="focusInput" style="margin:5px;" id="wafCreateNameInput" name="name" required size="50" maxlength="50"/>
                        <span class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
					</td>
				</tr>
				<tr>
					<td>Type</td>
					<td class="inputValue no-color">
						<select style="margin:5px;" id="typeSelect" name="wafType.id">
							<option ng-repeat="type in wafTypeList" value="{{ type.id }}">{{ type.name }}</option>
						</select>
					</td>
				</tr>
			</tbody>
		</table>
	</div>
	<%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
<script type="text/ng-template" id="editWafModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            Edit WAF {{ object.name }}
            <span class="delete-span">
                <a ng-show="waf.applications"
                   id="deleteWafButtonUnsuccessful"
                   class="btn btn-danger header-button"
                   ng-click="alert('WAFs with applications cannot be deleted.')">
                    Delete
                </a>
                <a ng-hide="waf.applications"
                   id="deleteWafButton"
                   class="btn btn-danger header-button"
                   ng-click="showDeleteDialog('WAF')">
                    Delete
                </a>
            </span>
        </h4>
    </div>
    <div ng-form="form" class="modal-body">
        <table class="modal-form-table">
            <tbody>
            <tr>
                <td class="">Name</td>
                <td class="inputValue no-color">
                    <input ng-model="object.name" type="text" focus-on="focusInput" id="wafCreateNameInput" name="name" required ng-maxlength="50"/>
                    <span id="nameRequiredError" class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                    <span id="characterLimitError" class="errors" ng-show="form.name.$dirty && form.name.$error.maxlength">Over 50 characters limit!</span>
                    <span id="otherNameError" class="errors" ng-show="object.name_error"> {{ object.name_error }}</span>
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
                    <span id="typeRequiredError" class="errors" ng-show="form.wafTypeId.$dirty && form.wafTypeId.$error.required">Type is required.</span>
                    <span id="wafTypeIdError" class="errors" ng-show="object.wafType_id_error"> {{ object.wafType_id_error }}</span>
                </td>
            </tr>
            </tbody>
        </table>
    </div>
	<%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>

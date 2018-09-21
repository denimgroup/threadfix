<script type="text/ng-template" id="managePolicyModal.html">

    <style>
        div {
            text-align: left;
        }
        .padding {
            margin-bottom: 10px;
        }
        .modal-body {
            max-height: 400px;
            overflow-y: auto;
        }
    </style>

    <div class="modal-header">
        <h4 id="myModalLabel">
            Manage Policies for {{ object.name }}
        </h4>
    </div>

    <div class="modal-body">
        <div id="policies">
            <div class="row-fluid padding">
                <div class="span1" id="acceptcriteriaCaret{{ object.name }}" style="width: 10px;" ng-click="togglePolicys(object)">
                    <div style="margin-top:10px">
                        <span ng-class="{ expanded: object.policysExpanded }" class="caret-right"></span>
                    </div>
                </div>
                <div class="span5">
                    <select ng-options="policy.name for policy in policies track by policy.id"
                            id="policySelect" ng-model="object.newPolicy"></select>
                </div>
                <div class="span2" style="padding-left: 10px">
                    <a class="btn btn-primary" id="addButton" ng-click="addNewPolicy(object.newPolicy)" ng-disabled="!object.newPolicy">Add</a>
                </div>
                <div class="span4">
                    <span ng-show="newPolicyLoading" class="spinner dark"></span>
                    <span class="errors" ng-show="object.newPolicyError"> {{ object.newPolicyError }}</span>
                </div>
            </div>
            <div class="row-fluid padding" ng-show="object.policysExpanded && (!object.policies || object.policies.length == 0)">
                <div class="span1" style="width: 10px"></div>
                <div class="span11">No Policies</div>
            </div>
            <div class="row-fluid padding" ng-show="object.policysExpanded && object.policies && object.policies.length > 0">
                <div class="row-fluid" ng-repeat="policy in object.policies">
                    <div class="span1" style="width: 10px"></div>
                    <div class="span11" id="policy{{ policy.name | removeSpace}}">
                        <span class="icon-remove icon-red" style="cursor: pointer" ng-click="deletePolicy(policy)"></span>
                        {{ policy.name }}
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal-footer">
        <span id="errorSpan" class="errors" style="float:left">{{ error }}</span>
        <a id="closeModalButton" class="btn" ng-click="cancel()">Close</a>
    </div>
</script>
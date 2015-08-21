<script type="text/ng-template" id="manageAcceptanceCriteriaModal.html">

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
            Acceptance Criteria for {{ object.name }}
        </h4>
    </div>

    <div class="modal-body">
        <div id="acceptanceCriterias">
            <div class="row-fluid padding">
                <div class="span1" id="acceptcriteriaCaret{{ object.name }}" style="width: 10px;" ng-click="toggleAcceptanceCriterias(object)">
                    <div style="margin-top:10px">
                        <span ng-class="{ expanded: object.acceptanceCriteriasExpanded }" class="caret-right"></span>
                    </div>
                </div>
                <div class="span5">
                    <select ng-options="acceptanceCriteria.name for acceptanceCriteria in acceptanceCriterias track by acceptanceCriteria.id"
                            id="acceptanceCriteriaSelect" ng-model="object.newAcceptanceCriteria"></select>
                </div>
                <div class="span2" style="padding-left: 10px">
                    <a class="btn btn-primary" id="addButton" ng-click="addNewAcceptanceCriteria(object.newAcceptanceCriteria)" ng-disabled="!object.newAcceptanceCriteria">Add</a>
                </div>
                <div class="span4">
                    <span ng-show="newAcceptanceCriteriaLoading" class="spinner dark"></span>
                    <span class="errors" ng-show="object.newAcceptanceCriteriaError"> {{ object.newAcceptanceCriteriaError }}</span>
                </div>
            </div>
            <div class="row-fluid padding" ng-show="object.acceptanceCriteriasExpanded && !object.acceptanceCriterias">
                <div class="span1" style="width: 10px"></div>
                <div class="span11">No Acceptance Criteria</div>
            </div>
            <div class="row-fluid padding" ng-show="object.acceptanceCriteriasExpanded && object.acceptanceCriterias">
                <div class="row-fluid" ng-repeat="acceptanceCriteria in object.acceptanceCriterias">
                    <div class="span1" style="width: 10px"></div>
                    <div class="span11" id="acceptcriteria{{ acceptanceCriteria.name | removeSpace}}">
                        <span class="icon-remove icon-red" style="cursor: pointer" ng-click="deleteAcceptanceCriteria(acceptanceCriteria)"></span>
                        {{ acceptanceCriteria.name }}
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
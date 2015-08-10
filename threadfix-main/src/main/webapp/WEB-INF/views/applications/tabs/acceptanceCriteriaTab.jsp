<tab id='vulnTab' heading="{{ acceptanceCriteriaStatuses.length }} Acceptance Criteria" ng-click="setTab('Acceptance Criteria')"
     active="tab.acceptanceCriteria" ng-show="acceptanceCriteriaStatuses">
    <div id="acceptanceCriteriaDiv${ application.id }">
        <table class="table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Filter Name</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
            <tr ng-hide="acceptanceCriteriaStatuses" class="bodyRow">
                <td id="noAcceptanceCriteriasFoundMessage" colspan="5" style="text-align:center;">No Acceptance Criteria found.</td>
            </tr>
            <tr class="bodyRow" ng-repeat="acceptanceCriteriaStatus in acceptanceCriteriaStatuses">
                <td id="acceptanceCriteriaName{{ $index }}"> {{ acceptanceCriteriaStatus.acceptanceCriteria.name }} </td>
                <td id="acFilterName{{ $index }}"> {{ acceptanceCriteriaStatus.acceptanceCriteria.filterName }} </td>
                <td id="acceptanceCriteriaStatus{{ $index }}">
                    <span id="acsStatusPass" ng-show="acceptanceCriteriaStatus.passing" class="badge" ng-class="{'badge-ac-status-passing': true}">PASS</span>
                    <span id="acsStatusFail" ng-hide="acceptanceCriteriaStatus.passing" class="badge" ng-class="{'badge-ac-status-failing': true}">FAIL</span>
                </td>
            </tr>
            </tbody>
        </table>
    </div>
</tab>
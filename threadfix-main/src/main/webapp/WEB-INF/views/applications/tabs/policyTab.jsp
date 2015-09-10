<tab id='vulnTab' heading="{{ policyStatuses.length }} Policy" ng-click="setTab('Policy')"
     active="tab.policy" ng-show="policyStatuses">
    <div id="policyDiv${ application.id }">
        <table class="table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Filter Name</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
            <tr ng-hide="policyStatuses" class="bodyRow">
                <td id="noPolicysFoundMessage" colspan="5" style="text-align:center;">No Policy found.</td>
            </tr>
            <tr class="bodyRow" ng-repeat="policyStatus in policyStatuses">
                <td id="policyName{{ $index }}"> {{ policyStatus.policy.name }} </td>
                <td id="acFilterName{{ $index }}"> {{ policyStatus.policy.filterName }} </td>
                <td id="policyStatus{{ $index }}">
                    <span id="policyStatusStatusPass" ng-show="policyStatus.passing" class="badge" ng-class="{'badge-ac-status-passing': true}">PASS</span>
                    <span id="policyStatusStatusFail" ng-hide="policyStatus.passing" class="badge" ng-class="{'badge-ac-status-failing': true}">FAIL</span>
                </td>
            </tr>
            </tbody>
        </table>
    </div>
</tab>
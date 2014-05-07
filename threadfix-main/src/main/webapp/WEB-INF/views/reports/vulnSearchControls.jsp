<div ng-controller="VulnSearchController">

    {{ parameters | json }}


    <div class="vuln-search-filter-control">
        Teams
        <br>
        <div ng-repeat="team in parameters.teams">
            <input typeahead="team.name for team in teams | filter:$viewValue | limitTo:8" type="text" ng-model="team.name" name="team"/>
            <span class="pointer icon icon-plus-sign" ng-click="addTeam()"></span>
            <span ng-show="parameters.teams.length > 1" class="pointer icon icon-minus-sign" ng-click="removeTeam($index)"></span>

        </div>
    </div>

    <div class="vuln-search-filter-control">
        Severity
        <div class="btn-group">
            <label class="btn" ng-model="parameters.severities.info" btn-checkbox>Info</label>
            <label class="btn" ng-model="parameters.severities.low" btn-checkbox>Low</label>
            <label class="btn" ng-model="parameters.severities.middle" btn-checkbox>Medium</label>
            <label class="btn" ng-model="parameters.severities.high" btn-checkbox>High</label>
            <label class="btn" ng-model="parameters.severities.critical" btn-checkbox>Critical</label>
        </div>
    </div>

    <div class="vuln-search-filter-control">
        Number Vulnerabilities
        <div class="btn-group">
            <label class="btn" ng-model="parameters.numToDisplay" btn-radio="10">10</label>
            <label class="btn" ng-model="parameters.numToDisplay" btn-radio="25">25</label>
            <label class="btn" ng-model="parameters.numToDisplay" btn-radio="50">50</label>
            <label class="btn" ng-model="parameters.numToDisplay" btn-radio="100">100</label>
        </div>
    </div>
</div>

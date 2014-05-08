<div ng-controller="VulnSearchController">
    {{ parameters | json }}

    <div class="vuln-search-filter-control">
        Teams
        <br>
        <div ng-repeat="filteredTeam in parameters.teams">
            <input typeahead="team.name for team in teams | filter:$viewValue | limitTo:8" type="text" ng-model="filteredTeam.name" name="team" typeahead-on-select="refresh()"/>
            <span class="pointer icon icon-plus-sign" ng-click="addTeam()"></span>
            <span ng-show="parameters.teams.length > 1" class="pointer icon icon-minus-sign" ng-click="removeTeam($index)"></span>
        </div>
    </div>

    <div class="vuln-search-filter-control">
        Severity
        <div class="btn-group">
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.info" btn-checkbox>Info</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.low" btn-checkbox>Low</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.medium" btn-checkbox>Medium</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.high" btn-checkbox>High</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.critical" btn-checkbox>Critical</label>
        </div>
    </div>

    <div class="vuln-search-filter-control">
        Number Vulnerabilities
        <ul class="nav nav-pills">
            <li ng-class="{ active: parameters.numberVulnerabilities === 10 }"><a ng-click="setNumberVulnerabilities(10)">10</a></li>
            <li ng-class="{ active: parameters.numberVulnerabilities === 25 }"><a ng-click="setNumberVulnerabilities(25)">25</a></li>
            <li ng-class="{ active: parameters.numberVulnerabilities === 50 }"><a ng-click="setNumberVulnerabilities(50)">50</a></li>
            <li ng-class="{ active: parameters.numberVulnerabilities === 100 }"><a ng-click="setNumberVulnerabilities(100)">100</a></li>
        </ul>
    </div>

    <%@ include file="vulnerabilityTable.jsp"%>

    {{ vulns | json }}
</div>

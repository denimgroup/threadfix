<div class="vuln-search-filter-control" ng-controller="VulnSearchController">
    {{ parameters | json }}

    <div>
        Teams
        <br>
        <div ng-repeat="filteredTeam in parameters.teams">
            <input typeahead="team.name for team in teams | filter:$viewValue | limitTo:8" type="text" ng-model="filteredTeam.name" typeahead-on-select="refresh()"/>
            <span class="pointer icon icon-plus-sign" ng-click="add(parameters.teams)"></span>
            <span ng-show="parameters.teams.length > 1" class="pointer icon icon-minus-sign" ng-click="remove(parameters.teams, $index)"></span>
        </div>
    </div>

    <div>
        Vulnerability Type
        <br>
        <div ng-repeat="filteredType in parameters.genericVulnerabilities">
            <input id="vulnerabilityTypeFilterInput" type="text"
                   class="form-control"
                   ng-model="filteredType.text"
                   typeahead="(vulnerability.name + ' (CWE ' + vulnerability.displayId + ')') for vulnerability in genericVulnerabilities | filter:$viewValue | limitTo:10"
                   typeahead-on-select="refresh()"/>
            <span class="pointer icon icon-plus-sign" ng-click="add(parameters.genericVulnerabilities)"></span>
            <span ng-show="parameters.genericVulnerabilities.length > 1" class="pointer icon icon-minus-sign" ng-click="remove(parameters.genericVulnerabilities, $index)"></span>
        </div>
    </div>

    <div>
        Scanners
        <br>
        <div ng-repeat="filteredScanner in parameters.scanners">
            <input typeahead="scanner.name for scanner in scanners | filter:$viewValue | limitTo:8" type="text" ng-model="filteredScanner.name" typeahead-on-select="refresh()"/>
            <span class="pointer icon icon-plus-sign" ng-click="add(parameters.scanners)"></span>
            <span ng-show="parameters.scanners.length > 1" class="pointer icon icon-minus-sign" ng-click="remove(parameters.scanners, $index)"></span>
        </div>
    </div>

    <div>
        Severity
        <div class="btn-group">
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.info" btn-checkbox>Info</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.low" btn-checkbox>Low</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.medium" btn-checkbox>Medium</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.high" btn-checkbox>High</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.critical" btn-checkbox>Critical</label>
        </div>
    </div>

    <div>
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

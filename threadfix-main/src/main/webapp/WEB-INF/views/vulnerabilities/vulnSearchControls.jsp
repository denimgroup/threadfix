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
        Applications
        <br>
        <div ng-repeat="filteredApplication in parameters.applications">
            <input typeahead="(application.team.name + ' / ' + application.name) for application in applications| filter:$viewValue | limitTo:8" type="text" ng-model="filteredApplication.name" typeahead-on-select="refresh()"/>
            <span class="pointer icon icon-plus-sign" ng-click="add(parameters.applications)"></span>
            <span ng-show="parameters.applications.length > 1" class="pointer icon icon-minus-sign" ng-click="remove(parameters.applications, $index)"></span>
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
        Path
        <input type="text" placeholder="Example: /login.jsp" ng-model="parameters.path"/>
    </div>

    <div>
        Parameter
        <input type="text" placeholder="Example: username" ng-model="parameters.parameter"/>
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
        <br>
        <div class="btn-group">
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.info" btn-checkbox>Info</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.low" btn-checkbox>Low</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.medium" btn-checkbox>Medium</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.high" btn-checkbox>High</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.severities.critical" btn-checkbox>Critical</label>
        </div>
    </div>

    <div>
        Status
        <br>
        <div class="btn-group">
            <label class="btn" ng-change="refresh()" ng-model="parameters.showOpen" btn-checkbox>Open</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.showClosed" btn-checkbox>Closed</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.showFalsePositive" btn-checkbox>False Positive</label>
            <label class="btn" ng-change="refresh()" ng-model="parameters.showHidden" btn-checkbox>Hidden</label>
        </div>
    </div>

    <div>
        Days Old
        <ul class="nav nav-pills">
            <li ng-class="{ active: parameters.daysOldModifier === 'Less' }"><a ng-click="setDaysOldModifier('Less')">Less Than</a></li>
            <li ng-class="{ active: parameters.daysOldModifier === 'More' }"><a ng-click="setDaysOldModifier('More')">More Than</a></li>
        </ul>
        <ul class="nav nav-pills">
            <li ng-class="{ active: parameters.daysOld === 7 }"><a ng-click="setDaysOld(7)">1 Week</a></li>
            <li ng-class="{ active: parameters.daysOld === 30 }"><a ng-click="setDaysOld(30)">30 days</a></li>
            <li ng-class="{ active: parameters.daysOld === 60 }"><a ng-click="setDaysOld(60)">60 days</a></li>
            <li ng-class="{ active: parameters.daysOld === 90 }"><a ng-click="setDaysOld(90)">90 days</a></li>
        </ul>
    </div>

    <h4>Start Date</h4>
    <div>
        <div class="col-md-6">
            <p class="input-group">
                <input type="text" class="form-control" ng-model="startDate" style="margin-bottom:0" datepicker-popup="dd-MMMM-yyyy" ng-model="startDate" is-open="startDateOpened" min-date="minDate" max-date="maxDate" date-disabled="disabled(date, mode)" close-text="Close" />
              <span class="input-group-btn">
                <button type="button" class="btn btn-default" ng-click="openStartDate($event)"><i class="icon icon-calendar"></i></button>
              </span>
            </p>
        </div>
    </div>

    <h4>End Date</h4>
    <div>
        <div class="col-md-6">
            <p class="input-group">
                <input type="text" class="form-control" ng-model="endDate" style="margin-bottom:0" datepicker-popup="dd-MMMM-yyyy" ng-model="endDate" is-open="endDateOpened" min-date="startDate" max-date="maxDate" date-disabled="disabled(date, mode)" close-text="Close" />
                <span class="input-group-btn">
                    <button type="button" class="btn btn-default" ng-click="openEndDate($event)"><i class="icon icon-calendar"></i></button>
                </span>
            </p>
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

    <div>
        Number Merged Findings
        <ul class="nav nav-pills">
            <li ng-class="{ active: parameters.numberMerged === 2 }"><a ng-click="setNumberMerged(2)">2+</a></li>
            <li ng-class="{ active: parameters.numberMerged === 3 }"><a ng-click="setNumberMerged(3)">3+</a></li>
            <li ng-class="{ active: parameters.numberMerged === 4 }"><a ng-click="setNumberMerged(4)">4+</a></li>
            <li ng-class="{ active: parameters.numberMerged === 5 }"><a ng-click="setNumberMerged(5)">5+</a></li>
        </ul>
    </div>

    <%@ include file="vulnerabilityTable.jsp"%>

    {{ vulns | json }}
</div>

<div class="vuln-search-filter-control" style="width:900px;" ng-controller="VulnSearchController">

    <div class="filter-controls">
        <h3>Filters</h3>

        <div class="accordion-group">
            <div class="accordion-heading" ng-click="showSaveAndLoadControls = !showSaveAndLoadControls">
                <span class="icon" ng-class="{ 'icon-minus': showSaveAndLoadControls, 'icon-plus': !showSaveAndLoadControls }"></span> Save and Load
            </div>
            <div ng-show="showSaveAndLoadControls" class="filter-group-body">
                <div class="accordion-inner">
                    <div ng-show="saveFilterSuccessMessage" class="alert alert-success">
                        <button class="close" ng-click="saveFilterSuccessMessage = undefined" type="button">&times;</button>
                        {{ saveFilterSuccessMessage }}
                    </div>
                    <div ng-show="saveFilterErrorMessage" class="alert alert-success">
                        <button class="close" ng-click="saveFilterErrorMessage = undefined" type="button">&times;</button>
                        {{ saveFilterErrorMessage }}
                    </div>
                    <input style="width: 193px;" placeholder="Put a name for the filter here." ng-model="currentFilterNameInput" type="text"/>
                    <a class="btn btn-primary" ng-hide="savingFilter" ng-disabled="!currentFilterNameInput" ng-click="saveCurrentFilters()">Save</a>
                    <button id="loadingButton"
                            ng-show="savingFilter"
                            disabled="disabled"
                            class="btn btn-primary">
                        <span class="spinner"></span>
                        Saving
                    </button>
                </div>
                <div ng-show="savedFilters" class="accordion-inner">
                    <div ng-show="deleteFilterSuccessMessage" class="alert alert-success">
                        <button class="close" ng-click="deleteFilterSuccessMessage = undefined" type="button">&times;</button>
                        {{ deleteFilterSuccessMessage }}
                    </div>
                    <select style="width: 207px;" ng-model="selectedFilter" ng-options="filter.name for filter in savedFilters">
                        <option>Select a Filter</option>
                    </select>
                    <a class="btn" ng-disabled="!selectedFilter || lastLoadedFilterName === selectedFilter.name" ng-click="loadFilter()">Load</a>
                    <a class="btn btn-danger" ng-disabled="!selectedFilter" ng-click="deleteFilter()"><span class="icon icon-white icon-trash"></span></a>
                </div>
            </div>
        </div>

        <div class="accordion-group">
            <div class="accordion-heading" ng-click="showTeamAndApplicationControls = !showTeamAndApplicationControls">
                <span class="icon" ng-class="{ 'icon-minus': showTeamAndApplicationControls, 'icon-plus': !showTeamAndApplicationControls }"></span> Team And Application Controls
            </div>
            <div ng-show="showTeamAndApplicationControls" class="filter-group-body">
                <div class="accordion-inner">
                    Teams
                    <a ng-hide="showTeamInput" ng-click="showTeamInput = !showTeamInput">
                        <span class="icon" ng-class="{ 'icon-minus': showTeamInput, 'icon-plus': !showTeamInput }"></span>
                    </a>
                    <br>
                    <input focus-on="showTeamInput"
                           ng-show="showTeamInput"
                           typeahead="team.name for team in teams | filter:$viewValue | limitTo:8"
                           type="text"
                           ng-model="newFilteredTeam.name"
                           typeahead-on-select="addNew(parameters.teams, newFilteredTeam.name); newFilteredTeam = {}; showTeamInput = false"/>
                    <div ng-repeat="filteredTeam in parameters.teams">
                        <span class="pointer icon icon-minus-sign" ng-click="remove(parameters.teams, $index)"></span>
                        {{ filteredTeam.name }}
                    </div>
                </div>

                <div class="accordion-inner">
                    Applications
                    <a ng-hide="showApplicationInput" ng-click="showApplicationInput = !showApplicationInput">
                        <span class="icon" ng-class="{ 'icon-minus': showApplicationInput, 'icon-plus': !showApplicationInput }"></span>
                    </a>
                    <br>
                    <input focus-on="showApplicationInput"
                           ng-show="showApplicationInput"
                           typeahead="(application.team.name + ' / ' + application.name) for application in applications | filter:$viewValue | limitTo:8"
                           type="text"
                           ng-model="newFilteredApplication.name"
                           typeahead-on-select="addNew(parameters.applications, newFilteredApplication.name); newFilteredApplication = {}; showApplicationInput = false"/>
                    <div ng-repeat="filteredApplication in parameters.applications">
                        <span class="pointer icon icon-minus-sign" ng-click="remove(parameters.applications, $index)"></span>
                        {{ filteredApplication.name }}
                    </div>
                </div>
            </div>
        </div>

        <div class="accordion-group">
            <div class="accordion-heading" ng-click="showTypeAndMergedControls = !showTypeAndMergedControls">
                <span class="icon" ng-class="{ 'icon-minus': showTypeAndMergedControls, 'icon-plus': !showTypeAndMergedControls }"></span> Type and # Merged Controls
            </div>
            <div class="filter-group-body" ng-show="showTypeAndMergedControls">
                <div class="accordion-inner" ng-hide="true">
                    Number Vulnerabilities
                    <ul class="nav nav-pills">
                        <li ng-class="{ active: parameters.numberVulnerabilities === 10 }"><a ng-click="setNumberVulnerabilities(10)">10</a></li>
                        <li ng-class="{ active: parameters.numberVulnerabilities === 25 }"><a ng-click="setNumberVulnerabilities(25)">25</a></li>
                        <li ng-class="{ active: parameters.numberVulnerabilities === 50 }"><a ng-click="setNumberVulnerabilities(50)">50</a></li>
                        <li ng-class="{ active: parameters.numberVulnerabilities === 100 }"><a ng-click="setNumberVulnerabilities(100)">100</a></li>
                    </ul>
                </div>

                <div class="accordion-inner">
                    Number Merged Findings
                    <ul class="nav nav-pills">
                        <li ng-class="{ active: parameters.numberMerged === 2 }"><a ng-click="setNumberMerged(2)">2+</a></li>
                        <li ng-class="{ active: parameters.numberMerged === 3 }"><a ng-click="setNumberMerged(3)">3+</a></li>
                        <li ng-class="{ active: parameters.numberMerged === 4 }"><a ng-click="setNumberMerged(4)">4+</a></li>
                        <li ng-class="{ active: parameters.numberMerged === 5 }"><a ng-click="setNumberMerged(5)">5+</a></li>
                    </ul>
                </div>

                <div class="accordion-inner">
                    Vulnerability Type
                    <a ng-hide="showTypeInput" ng-click="showTypeInput = !showTypeInput">
                        <span class="icon" ng-class="{ 'icon-minus': showTypeInput, 'icon-plus': !showTypeInput }"></span>
                    </a>
                    <br>
                    <input ng-show="showTypeInput"
                           focus-on="showTypeInput"
                           id="vulnerabilityTypeFilterInput"
                           type="text"
                           class="form-control"
                           ng-model="newFilteredType.text"
                           typeahead="(vulnerability.name + ' (CWE ' + vulnerability.displayId + ')') for vulnerability in genericVulnerabilities | filter:$viewValue | limitTo:10"
                           typeahead-on-select="addNew(parameters.genericVulnerabilities, newFilteredType.text); newFilteredType = {}; showTypeInput = false"/>
                    <div ng-repeat="filteredType in parameters.genericVulnerabilities">
                        <span class="pointer icon icon-minus-sign" ng-click="remove(parameters.genericVulnerabilities, $index)"></span>
                        {{ filteredType.name | shortCweNames }}
                    </div>
                </div>

                <div class="accordion-inner">
                    Scanners
                    <a ng-hide="showScannerInput" ng-click="showScannerInput = !showScannerInput">
                        <span class="icon" ng-class="{ 'icon-minus': showScannerInput, 'icon-plus': !showScannerInput }"></span>
                    </a>
                    <br>
                    <input ng-show="showScannerInput"
                           focus-on="showScannerInput"
                           typeahead="scanner.name for scanner in scanners | filter:$viewValue | limitTo:8"
                           type="text"
                           ng-model="newFilteredScanner.name"
                           typeahead-on-select="addNew(parameters.scanners, newFilteredScanner.name); newFilteredScanner = {}; showScannerInput = false"/>
                    <div ng-repeat="filteredScanner in parameters.scanners">
                        <span class="pointer icon icon-minus-sign" ng-click="remove(parameters.scanners, $index)"></span>
                        {{ filteredScanner.name }}
                    </div>
                </div>
            </div>
        </div>

        <div class="accordion-group">
            <div class="accordion-heading" ng-click="showDetailsControls = !showDetailsControls">
                <span class="icon" ng-class="{ 'icon-minus': showDetailsControls, 'icon-plus': !showDetailsControls }"></span> Details Controls
            </div>
            <div class="filter-group-body" ng-show="showDetailsControls">
                <div class="accordion-inner">
                    Path
                    <br>
                    <input type="text" placeholder="Example: /login.jsp" ng-model="parameters.path"/>
                </div>

                <div class="accordion-inner">
                    Parameter
                    <br>
                    <input type="text" placeholder="Example: username" ng-model="parameters.parameter"/>
                </div>

                <div class="accordion-inner">
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

                <div class="accordion-inner">
                    Status
                    <br>
                    <div class="btn-group">
                        <label class="btn" ng-change="refresh()" ng-model="parameters.showOpen" btn-checkbox>Open</label>
                        <label class="btn" ng-change="refresh()" ng-model="parameters.showClosed" btn-checkbox>Closed</label>
                        <label class="btn" ng-change="refresh()" ng-model="parameters.showFalsePositive" btn-checkbox>False Positive</label>
                        <label class="btn" ng-change="refresh()" ng-model="parameters.showHidden" btn-checkbox>Hidden</label>
                    </div>
                </div>
            </div>
        </div>

        <div class="accordion-group">
            <div class="accordion-heading" ng-click="showDateControls = !showDateControls">
                <span class="icon" ng-class="{ 'icon-minus': showDateControls, 'icon-plus': !showDateControls }"></span> Date Controls
            </div>
            <div class="filter-group-body" ng-show="showDateControls">
                <div class="accordion-inner">
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

                <div class="accordion-inner">
                    <h4>Start Date</h4>
                    <div class="col-md-6">
                        <p class="input-group">
                            <input type="text" class="form-control" ng-model="startDate" style="margin-bottom:0" datepicker-popup="dd-MMMM-yyyy" ng-model="startDate" is-open="startDateOpened" min-date="minDate" max-date="maxDate" date-disabled="disabled(date, mode)" close-text="Close" />
                          <span class="input-group-btn">
                            <button type="button" class="btn btn-default" ng-click="openStartDate($event)"><i class="icon icon-calendar"></i></button>
                          </span>
                        </p>
                    </div>
                </div>

                <div class="accordion-inner">
                    <h4>End Date</h4>
                    <div class="col-md-6">
                        <p class="input-group">
                            <input type="text" class="form-control" ng-model="endDate" style="margin-bottom:0" datepicker-popup="dd-MMMM-yyyy" ng-model="endDate" is-open="endDateOpened" min-date="startDate" max-date="maxDate" date-disabled="disabled(date, mode)" close-text="Close" />
                            <span class="input-group-btn">
                                <button type="button" class="btn btn-default" ng-click="openEndDate($event)"><i class="icon icon-calendar"></i></button>
                            </span>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <%@ include file="vulnSearchTree.jsp" %>
    <%@ include file="vulnerabilityTable.jsp" %>

    {{ vulns | json }}
</div>

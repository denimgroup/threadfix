
<!-- Clear / select all -->
<div class="accordion-group">
    <div class="accordion-heading" style="text-align:center">
        <a id="toggleAllButton" class="btn" ng-click="toggleAllFilters()">
            {{ (showSaveAndLoadControls || showTeamAndApplicationControls || showDetailsControls || showDateControls || showDateRange || showTypeAndMergedControls || showSaveFilter) ? 'Collapse' : 'Expand' }} All
        </a>
        <a id="clearFiltersButton" class="btn" ng-click="reset()">Clear</a>
    </div>
</div>


<!-- Teams and Applications section (should only show on Reports page -->
<div class="accordion-group" ng-hide="treeApplication || treeTeam || complianceActive || remediationEnterpriseActive">
    <div class="accordion-heading" ng-click="showTeamAndApplicationControls = !showTeamAndApplicationControls">
        <span id="expandTeamAndApplicationFilters" class="icon" ng-class="{ 'icon-minus': showTeamAndApplicationControls, 'icon-plus': !showTeamAndApplicationControls }"></span> Teams And Applications
    </div>
    <div ng-show="showTeamAndApplicationControls" class="filter-group-body">
        <div class="accordion-inner">
            Teams
            <a ng-hide="showTeamInput" ng-click="showTeamInput = !showTeamInput">
                <span id="showTeamInput" class="icon" ng-class="{ 'icon-minus': showTeamInput, 'icon-plus': !showTeamInput }"></span>
            </a>
            <br>
            <input id="teamNameTypeahead" focus-on="showTeamInput"
                   ng-show="showTeamInput"
                   typeahead="team.name for team in teams | filter:$viewValue | limitTo:8"
                   type="text"
                   ng-model="newFilteredTeam.name"
                   typeahead-on-select="addNew(parameters.teams, newFilteredTeam.name); newFilteredTeam = {}; showTeamInput = false"/>
            <div ng-repeat="filteredTeam in parameters.teams">
                <span id="removeTeam{{ filteredTeam.name }}" class="pointer icon icon-minus-sign" ng-click="remove(parameters.teams, $index)"></span>
                {{ filteredTeam.name }}
            </div>
        </div>

        <div class="accordion-inner">
            Applications
            <a ng-hide="showApplicationInput" ng-click="showApplicationInput = !showApplicationInput">
                <span id="showApplicationInput" class="icon" ng-class="{ 'icon-minus': showApplicationInput, 'icon-plus': !showApplicationInput }"></span>
            </a>
            <br>
            <input id="applicationNameTypeahead"
                   focus-on="showApplicationInput"
                   ng-show="showApplicationInput"
                   typeahead="(application.team.name + ' / ' + application.name) for application in searchApplications | filter:$viewValue | limitTo:8"
                   type="text"
                   ng-model="newFilteredApplication.name"
                   typeahead-on-select="addNew(parameters.applications, newFilteredApplication.name); newFilteredApplication = {}; showApplicationInput = false"/>
            <div ng-repeat="filteredApplication in parameters.applications">
                <span id="removeApplication{{ filteredApplication.name }}" class="pointer icon icon-minus-sign" ng-click="remove(parameters.applications, $index)"></span>
                {{ filteredApplication.name }}
            </div>
        </div>
    </div>
</div>

<!-- This is the same as the above control but only shows up on the team page. -->
<div class="accordion-group" ng-show="treeTeam">
    <div class="accordion-heading" ng-click="showTeamAndApplicationControls = !showTeamAndApplicationControls">
        <span id="expandApplicationFilters" class="icon" ng-class="{ 'icon-minus': showTeamAndApplicationControls, 'icon-plus': !showTeamAndApplicationControls }"></span> Teams And Applications
    </div>
    <div ng-show="showTeamAndApplicationControls" class="filter-group-body">

        <div class="accordion-inner">
            Applications
            <a ng-hide="showApplicationInput" ng-click="showApplicationInput = !showApplicationInput">
                <span id="showApplicationInput1" class="icon" ng-class="{ 'icon-minus': showApplicationInput, 'icon-plus': !showApplicationInput }"></span>
            </a>
            <br>
            <input id="applicationNameTypeahead1"
                   focus-on="showApplicationInput"
                   ng-show="showApplicationInput"
                   typeahead="(treeTeam.name + ' / ' + application.name) for application in treeTeam.applications | filter:$viewValue | limitTo:8"
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

<!-- Tags. -->
<div class="accordion-group" ng-show="treeTeam || vulnSearch || complianceActive">
    <div class="accordion-heading" ng-click="showTagControls = !showTagControls">
        <span id="expandTagFilters" class="icon" ng-class="{ 'icon-minus': showTagControls, 'icon-plus': !showTagControls }"></span> Tags
    </div>
    <div ng-show="showTagControls" class="filter-group-body">

        <div class="accordion-inner">
            Applications
            <a ng-hide="showTagInput" ng-click="showTagInput = !showTagInput">
                <span id="showTagInput" class="icon" ng-class="{ 'icon-minus': showTagInput, 'icon-plus': !showTagInput }"></span>
            </a>
            <br>
            <input id="tagNameTypeahead"
                   focus-on="showTagInput"
                   ng-show="showTagInput"
                   typeahead="tag.name for tag in tags | filter:$viewValue | limitTo:8"
                   type="text"
                   ng-model="newFilteredTag.name"
                   typeahead-on-select="addNew(parameters.tags, newFilteredTag.name); newFilteredTag = {}; showTagInput = false"/>
            <div ng-repeat="filteredTag in parameters.tags">
                <span class="pointer icon icon-minus-sign" ng-click="remove(parameters.tags, $index)"></span>
                {{ filteredTag.name }}
            </div>
        </div>
    </div>
</div>

<!-- Scanner and # Merged controls -->
<div class="accordion-group" ng-show="treeTeam || vulnSearch || treeApplication">
    <div class="accordion-heading" ng-click="showTypeAndMergedControls = !showTypeAndMergedControls">
        <span id="expandScannerFilters" class="icon" ng-class="{ 'icon-minus': showTypeAndMergedControls, 'icon-plus': !showTypeAndMergedControls }"></span> Scanner and # Merged
    </div>
    <div class="filter-group-body" ng-show="showTypeAndMergedControls">

        <div class="accordion-inner">
            Number Merged Findings
            <ul class="nav nav-pills">
                <li id="set2MergedFindings" ng-class="{ active: parameters.numberMerged === 2 }"><a ng-click="setNumberMerged(2)">2+</a></li>
                <li id="set3MergedFindings" ng-class="{ active: parameters.numberMerged === 3 }"><a ng-click="setNumberMerged(3)">3+</a></li>
                <li id="set4MergedFindings" ng-class="{ active: parameters.numberMerged === 4 }"><a ng-click="setNumberMerged(4)">4+</a></li>
                <li id="set5MergedFindings" ng-class="{ active: parameters.numberMerged === 5 }"><a ng-click="setNumberMerged(5)">5+</a></li>
            </ul>
        </div>

        <div class="accordion-inner">
            Scanners
            <a ng-hide="showScannerInput" ng-click="showScannerInput = !showScannerInput">
                <span id="showScannerInput" class="icon" ng-class="{ 'icon-minus': showScannerInput, 'icon-plus': !showScannerInput }"></span>
            </a>
            <br>
            <input id="scannerTypeahead"
                   ng-show="showScannerInput"
                   focus-on="showScannerInput"
                   typeahead="scanner.name for scanner in scanners | filter:$viewValue | limitTo:8"
                   type="text"
                   ng-model="newFilteredScanner.name"
                   typeahead-on-select="addNew(parameters.scanners, newFilteredScanner.name); newFilteredScanner = {}; showScannerInput = false"/>
            <div ng-repeat="filteredScanner in parameters.scanners">
                <span id="removeScanner{{ filteredScanner.name }}" class="pointer icon icon-minus-sign" ng-click="remove(parameters.scanners, $index)"></span>
                {{ filteredScanner.name }}
            </div>
        </div>
    </div>
</div>

<!-- Field Controls: Type, path, parameter, etc. -->
<div class="accordion-group">
    <div class="accordion-heading" ng-click="showDetailsControls = !showDetailsControls">
        <span id="showFieldControls" class="icon" ng-class="{ 'icon-minus': showDetailsControls, 'icon-plus': !showDetailsControls }"></span> Field Controls
    </div>
    <div class="filter-group-body" ng-show="showDetailsControls">

        <div ng-show="treeTeam || vulnSearch || treeApplication">
            <div class="accordion-inner">
                Vulnerability Type
                <a ng-hide="showTypeInput" ng-click="showTypeInput = !showTypeInput">
                    <span id="showTypeInput" class="icon" ng-class="{ 'icon-minus': showTypeInput, 'icon-plus': !showTypeInput }"></span>
                </a>
                <br>
                <input id="vulnerabilityTypeTypeahead"
                       ng-show="showTypeInput"
                       focus-on="showTypeInput"
                       type="text"
                       class="form-control"
                       ng-model="newFilteredType.text"
                       typeahead="(vulnerability.name + ' (CWE ' + vulnerability.displayId + ')') for vulnerability in genericVulnerabilities | filter:$viewValue | limitTo:10"
                       typeahead-on-select="addNew(parameters.genericVulnerabilities, newFilteredType.text); newFilteredType = {}; showTypeInput = false"/>
                <div ng-repeat="filteredType in parameters.genericVulnerabilities">
                    <span id="removeType{{ filteredType.displayId }}" class="pointer icon icon-minus-sign" ng-click="remove(parameters.genericVulnerabilities, $index)"></span>
                    {{ filteredType.name | shortCweNames }}
                </div>
            </div>

            <div class="accordion-inner">
                Path
                <br>
                <input id="pathInput" style="width: 180px;" type="text" placeholder="Example: /login.jsp"
                       ng-model="parameters.path" ng-blur="refresh()" ng-enter="refresh()"/>
            </div>

            <div class="accordion-inner">
                Parameter
                <br>
                <input id="parameterFilterInput" style="width: 180px;" type="text" placeholder="Example: username"
                       ng-model="parameters.parameter" ng-blur="refresh()" ng-enter="refresh()"/>
            </div>
        </div>

        <div class="accordion-inner">
            Severity
            <br>
            <div>
                <input id="showInfo" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.info"/>Info<br>
                <input id="showLow" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.low"/>Low<br>
                <input id="showMedium" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.medium"/>Medium<br>
                <input id="showHigh" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.high"/>High<br>
                <input id="showCritical" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.critical"/>Critical
            </div>
        </div>

        <div class="accordion-inner" ng-show="treeTeam || vulnSearch || treeApplication || trendingActive">
            Status
            <br>
            <div>
                <div ng-show="treeTeam || vulnSearch || treeApplication">
                    <input id="showOpen" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showOpen"/>Open<br>
                    <input id="showFalsePositive" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showFalsePositive"/>False Positive<br>
                </div>
                <div ng-show="trendingActive">
                    <input id="showOldReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showOld"/>Old<br>
                    <input id="showNewReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showNew"/>New<br>
                    <input id="showResurfacedReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showResurfaced"/>Resurfaced<br>
                </div>
                <input id="showClosed" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showClosed"/>Closed<br>
                <input id="showHidden" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showHidden"/>Hidden
            </div>
        </div>

        <div class="accordion-inner" ng-show="trendingActive">
            Other
            <br>
            <div>
                <input id="showTotalReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showTotal"/>Total<br>
            </div>
        </div>

        <div class="accordion-inner" ng-show="treeTeam || vulnSearch || treeApplication">
            Defect
            <br>
            <div>
                <input id="showDefectPresent" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showDefectPresent"/>Present<br>
                <input id="showDefectNotPresent" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showDefectNotPresent"/>Not Present<br>
                <input id="showDefectOpen" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showDefectOpen"/>Open<br>
                <input id="showDefectClosed" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showDefectClosed"/>Closed
            </div>
        </div>
    </div>
</div>

<!-- Aging -->
<div class="accordion-group" ng-hide="snapshotActive">
    <div class="accordion-heading" ng-click="showDateControls = !showDateControls">
        <span id="showDateControls" class="icon" ng-class="{ 'icon-minus': showDateControls, 'icon-plus': !showDateControls }"></span> Aging
    </div>
    <div class="filter-group-body" ng-show="showDateControls">
        <div class="accordion-inner" ng-show="treeTeam || vulnSearch || treeApplication">
            Days Old
            <ul class="nav nav-pills">
                <li id="lessThan" ng-class="{ active: parameters.daysOldModifier === 'Less' }"><a ng-click="setDaysOldModifier('Less')">Less Than</a></li>
                <li id="moreThan" ng-class="{ active: parameters.daysOldModifier === 'More' }"><a ng-click="setDaysOldModifier('More')">More Than</a></li>
            </ul>
            <ul class="nav nav-pills">
                <li id="oneWeek" ng-class="{ active: parameters.daysOld === 7 }"><a ng-click="setDaysOld(7)">1 Week</a></li>
                <li id="30days" ng-class="{ active: parameters.daysOld === 30 }"><a ng-click="setDaysOld(30)">30 days</a></li>
                <li id="60days" ng-class="{ active: parameters.daysOld === 60 }"><a ng-click="setDaysOld(60)">60 days</a></li>
                <li id="90days" ng-class="{ active: parameters.daysOld === 90 }"><a ng-click="setDaysOld(90)">90 days</a></li>
            </ul>
        </div>

        <div class="accordion-inner" ng-hide="treeTeam || vulnSearch || treeApplication">
            Days Old
            <ul class="nav nav-pills">
                <li id="lastYearReport" ng-class="{ active: parameters.daysOldModifier === 'LastYear' }"><a ng-click="setDaysOldModifier('LastYear')">Last Year</a></li>
                <li id="lastQuarterReport" ng-class="{ active: parameters.daysOldModifier === 'LastQuarter' }"><a ng-click="setDaysOldModifier('LastQuarter')">Last Quarter</a></li>
                <li id="foreverReport" ng-class="{ active: parameters.daysOldModifier === 'Forever' }"><a ng-click="setDaysOldModifier('Forever')">Forever</a></li>
            </ul>
        </div>

    </div>
</div>

<!-- Date Range -->
<div class="accordion-group" ng-hide="snapshotActive">
    <div class="accordion-heading" ng-click="showDateRange = !showDateRange">
        <span id="showDateRange" class="icon" ng-class="{ 'icon-minus': showDateRange, 'icon-plus': !showDateRange }"></span> Date Range
    </div>
    <div class="filter-group-body" ng-show="showDateRange">
        <div class="accordion-inner">
            <h4>Start Date</h4>
            <div class="col-md-6">
                <p class="input-group">
                    <input id="startDateInput" type="text" class="form-control" ng-model="startDate" style="width:135px;margin-bottom:0" datepicker-popup="dd-MMMM-yyyy" ng-model="startDate"
                           is-open="startDateOpened" min-date="minDate" max-date="maxDate" date-disabled="disabled(date, mode)" close-text="Close"
                           ng-change="refresh()"
                            />
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
                    <input id="endDateInput" type="text" class="form-control" ng-model="endDate" style="width:135px;margin-bottom:0" datepicker-popup="dd-MMMM-yyyy" ng-model="endDate"
                           is-open="endDateOpened" min-date="startDate" max-date="maxDate" date-disabled="disabled(date, mode)" close-text="Close"
                           ng-change="refresh()"
                            />
                    <span class="input-group-btn">
                        <button type="button" class="btn btn-default" ng-click="openEndDate($event)"><i class="icon icon-calendar"></i></button>
                    </span>
                </p>
            </div>
        </div>
    </div>
</div>

<!-- Save Filter -->
<div class="accordion-group" ng-hide="remediationEnterpriseActive">
    <div class="accordion-heading" ng-click="showSaveFilter = !showSaveFilter">
        <span id="showSaveFilter" class="icon" ng-class="{ 'icon-minus': showSaveFilter, 'icon-plus': !showSaveFilter }"></span> Save Current Filter
    </div>
    <div class="filter-group-body" ng-show="showSaveFilter">
        <div class="accordion-inner">
            <div class="col-md-6">
                <div id="saveFilterSuccessMessage" ng-show="saveFilterSuccessMessage" class="alert alert-success">
                    <button id="closeSaveFilterSuccessMessage"
                            class="close"
                            ng-click="saveFilterSuccessMessage = undefined"
                            type="button">&times;</button>
                    {{ saveFilterSuccessMessage }}
                </div>
                <div id="saveFilterErrorMessage" ng-show="saveFilterErrorMessage" class="alert alert-error">
                    <button id="closeSaveFilterErrorMessage"
                            class="close"
                            ng-click="saveFilterErrorMessage = undefined"
                            type="button">&times;</button>
                    {{ saveFilterErrorMessage }}
                </div>
                <input id="filterNameInput"
                       ng-maxlength="25"
                       placeholder="Enter a name for the filter"
                       ng-model="currentFilterNameInput"
                       type="text"/>

                <!-- Save button and save button with spinner. -->
                <a id="saveFilterButton"
                   class="btn btn-primary"
                   style="width:168px"
                   ng-hide="savingFilter"
                   ng-disabled="!currentFilterNameInput"
                   ng-click="saveCurrentFilters()">
                    Save
                </a>
                <button id="savingFilterButton"
                        ng-show="savingFilter"
                        disabled="disabled"
                        class="btn btn-primary">
                    <span class="spinner"></span>
                    Saving
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Export buttons -->
<security:authorize ifAnyGranted="ROLE_CAN_GENERATE_REPORTS">
    <div class="accordion-group" ng-show="treeTeam || vulnSearch || treeApplication || reportId === 3">
        <div class="accordion-heading" style="text-align:center">
            <a id="exportCSVButton" ng-click="exportCSV(reportId)" class="btn">Export CSV</a>
        </div>
    </div>

    <div class="accordion-group"  ng-hide="treeTeam || vulnSearch || treeApplication || reportId === 3">
        <div class="accordion-heading" style="text-align:center">
            <a id="exportPNGButtonReport" class="btn"
               ng-click="exportPNG()">Export PNG</a>
        </div>
    </div>
</security:authorize>
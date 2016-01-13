
<%@ include file="newDateForm.jsp" %>

<!-- Clear / select all -->
<div class="accordion-group">
    <div class="accordion-heading" style="text-align:center">
        <a id="toggleAllButton" class="btn" ng-click="toggleAllFilters()">
            {{ (showSaveAndLoadControls || showTeamAndApplicationControls || showDetailsControls || showDateControls || showDateRange || showTypeAndMergedControls || showSaveFilter || showPermissions) ? 'Collapse' : 'Expand' }} All
        </a>
        <a id="clearFiltersButton" class="btn" ng-click="reset()">Clear</a>
    </div>
</div>


<!-- Teams and Applications section (should only show on Reports page -->
<div class="accordion-group" ng-hide="treeApplication || treeTeam || complianceActive || remediationActive">
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
            <div ng-repeat="filteredTeam in parameters.teams" class="break-word-header">
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
            <div ng-repeat="filteredApplication in parameters.applications" class="break-word-header">
                <span id="removeApplication{{ filteredApplication.name }}" class="pointer icon icon-minus-sign" ng-click="remove(parameters.applications, $index)"></span>
                {{ filteredApplication.name }}
            </div>
        </div>

        <div class="accordion-inner" ng-show="trendingActive">
            Unique IDs
            <a ng-hide="showUniqueIdInput" ng-click="showUniqueIdInput = !showUniqueIdInput">
                <span id="showUniqueIdInput" class="icon" ng-class="{ 'icon-minus': showUniqueIdInput, 'icon-plus': !showUniqueIdInput }"></span>
            </a>
            <br>
            <input id="uniqueIdTypeahead"
                   focus-on="showUniqueIdInput"
                   ng-show="showUniqueIdInput"
                   typeahead="uniqueApp.uniqueId for uniqueApp in searchUniqueIds | filter:$viewValue | limitTo:8"
                   type="text"
                   ng-model="newFilteredUniqueId.uniqueId"
                   typeahead-on-select="addNew(parameters.uniqueIds, newFilteredUniqueId.uniqueId); newFilteredUniqueId = {}; showUniqueIdInput = false"/>
            <div ng-repeat="uniqueId in parameters.uniqueIds" class="break-word-header">
                <span id="removeUniqueId{{ uniqueId.name }}" class="pointer icon icon-minus-sign" ng-click="remove(parameters.uniqueIds, $index)"></span>
                {{ uniqueId.name }}
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
            <div ng-repeat="filteredApplication in parameters.applications" class="break-word-header">
                <span class="pointer icon icon-minus-sign" ng-click="remove(parameters.applications, $index)"></span>
                {{ filteredApplication.name }}
            </div>
        </div>
    </div>
</div>

<!-- Pivots -->
<div class="accordion-group" ng-show="treeTeam || treeApplication || vulnSearch || complianceActive || snapshotActive">
    <div class="accordion-heading" ng-click="showPivotControls = !showPivotControls">
        <span id="expandPivotFilters" class="icon" ng-class="{ 'icon-minus': showPivotControls, 'icon-plus': !showPivotControls }"></span> Pivots
    </div>
    <div ng-show="showPivotControls" class="filter-group-body">
        <div class="accordion-inner">
            Primary Pivot<br/>
            <select class="pivot" ng-options="vulnSearchPivotDisplayNames[pivot] for pivot in vulnSearchPivots"
                    ng-model="parameters.primaryPivot" name="primaryPivot" id="primaryPivot"
                    ng-change="validatePrimaryPivot(parameters.primaryPivot)"></select>
            <span class="errors" ng-show="primaryPivot_error">{{ primaryPivot_error }}</span>
        </div>
        <div class="accordion-inner">
            Secondary Pivot<br/>
            <select class="pivot" ng-options="vulnSearchPivotDisplayNames[pivot] for pivot in vulnSearchPivots"
                    ng-model="parameters.secondaryPivot" name="secondaryPivot" id="secondaryPivot"
                    ng-change="validateSecondaryPivot(parameters.secondaryPivot)"></select>
            <span class="errors" ng-show="secondaryPivot_error">{{ secondaryPivot_error }}</span>
        </div>
    </div>
</div>

<!-- Tags -->
<div class="accordion-group" ng-show="treeTeam || vulnSearch || complianceActive || trendingActive || snapshotActive || treeApplication">
    <div class="accordion-heading" ng-click="showTagControls = !showTagControls">
        <span id="expandTagFilters" class="icon" ng-class="{ 'icon-minus': showTagControls, 'icon-plus': !showTagControls }"></span> Tags
    </div>
    <div ng-show="showTagControls" class="filter-group-body">

        <div class="accordion-inner" ng-hide="treeApplication">
            Application
            <a ng-hide="showTagInput" ng-click="showTagInput = !showTagInput">
                <span id="showTagInput" class="icon" ng-class="{ 'icon-minus': showTagInput, 'icon-plus': !showTagInput }"></span>
            </a>
            <br>
            <input id="tagNameTypeahead"
                   focus-on="showTagInput"
                   ng-show="showTagInput"
                   typeahead="tag as tag.encodedName for tag in tags | filter:$viewValue | limitTo:8"
                   type="text"
                   ng-model="newFilteredTag"
                   typeahead-on-select="addNew(parameters.tags, newFilteredTag.name); newFilteredTag = ''; showTagInput = false"/>
            <div ng-repeat="filteredTag in parameters.tags" class="break-word-header">
                <span class="pointer icon icon-minus-sign" ng-click="remove(parameters.tags, $index)"></span>
                {{ filteredTag.name }}
            </div>
        </div>

        <div class="accordion-inner" ng-hide="complianceActive || trendingActive || (reportId && reportId == Portfolio_Report_Id)">
            Vulnerability
            <a ng-hide="showVulnTagInput" ng-click="showVulnTagInput = !showVulnTagInput">
                <span id="showVulnTagInput" class="icon" ng-class="{ 'icon-minus': showVulnTagInput, 'icon-plus': !showVulnTagInput }"></span>
            </a>
            <br>
            <input id="vulnTagNameTypeahead"
                   focus-on="showVulnTagInput"
                   ng-show="showVulnTagInput"
                   typeahead="tag.name for tag in vulnTags | filter:$viewValue | limitTo:8"
                   type="text"
                   ng-model="newFilteredVulnTag.name"
                   typeahead-on-select="addNew(parameters.vulnTags, newFilteredVulnTag.name); newFilteredVulnTag = {}; showVulnTagInput = false"/>
            <div ng-repeat="filteredTag in parameters.vulnTags" class="break-word-header">
                <span class="pointer icon icon-minus-sign" ng-click="remove(parameters.vulnTags, $index)"></span>
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
<div class="accordion-group"  ng-hide="reportId && reportId == OWASP_Report_Id">
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
                Defect ID
                <br>
                <input id="defectIdInput" style="width: 180px;" type="text" placeholder="Example: PROJECT-808"
                       ng-model="parameters.defectId" ng-blur="refresh()" ng-enter="refresh()"/>
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

            <div class="accordion-inner">
                Native Id
                <br>
                <input id="nativeIdInput" style="width: 180px;" type="text" placeholder="Example: 93ebd4..."
                       ng-model="parameters.nativeId" ng-blur="refresh()" ng-enter="refresh()"/>
            </div>
        </div>

        <div class="accordion-inner">
            Severity
            <br>
            <div>
                <input type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.critical" id="showCritical"/><span generic-severity="Critical" id="showCriticalText" class="break-word-header"></span><br>
                <input type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.high" id="showHigh"/><span generic-severity="High" id="showHighText" class="break-word-header"></span><br>
                <input type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.medium" id="showMedium"/><span generic-severity="Medium" id="showMediumText" class="break-word-header"></span><br>
                <input type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.low" id="showLow"/><span generic-severity="Low" id="showLowText" class="break-word-header"></span><br>
                <input type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.info" id="showInfo"/><span generic-severity="Info" id="showInfoText" class="break-word-header"></span>
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
                <input id="showDefectClosed" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showDefectClosed"/>Closed<br>
            </div>
        </div>

        <div class="accordion-inner" ng-show="treeTeam || vulnSearch || treeApplication">
            Remediation
            <br>
            <div>
                <span tooltip="The defect's status has been closed since the last scan updated this vulnerability, but the vulnerability is still open.">
                    <input id="showInconsistentClosedDefectNeedsScan" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showInconsistentClosedDefectNeedsScan"/>Needs Scan
                </span><br>
                <span tooltip="The defect is closed, but a scan has shown the vulnerability is still open since the defect's status was last updated.">
                    <input id="showInconsistentClosedDefectOpenInScan" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showInconsistentClosedDefectOpenInScan"/>Remediation Failure
                </span><br>
                <span tooltip="The vulnerability is closed, but the defect is still open.">
                    <input id="showInconsistentOpenDefect" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showInconsistentOpenDefect"/>Needs Verification
                </span>
            </div>
        </div>

        <div class="accordion-inner" ng-show="treeTeam || vulnSearch || treeApplication">
            Comment
            <br>
            <div>
                <input id="showCommentPresent" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showCommentPresent"/>Present<br>
            </div>
            <div>
                Tags
                <a ng-hide="showCommentTagInput" ng-click="showCommentTagInput = !showCommentTagInput">
                    <span id="showCommentTagInput" class="icon" ng-class="{ 'icon-minus': showCommentTagInput, 'icon-plus': !showCommentTagInput }"></span>
                </a>
                <br>
                <input id="commentTagNameTypeahead"
                       focus-on="showCommentTagInput"
                       ng-show="showCommentTagInput"
                       typeahead="tag as tag.name for tag in commentTags | filter:$viewValue | limitTo:8"
                       type="text"
                       ng-model="newFilteredCommentTag"
                       typeahead-on-select="addNewObject(parameters.commentTags, newFilteredCommentTag); newFilteredCommentTag = undefined; showCommentTagInput = false"/>
                <div ng-repeat="filteredTag in parameters.commentTags" class="break-word-header">
                    <span class="pointer icon icon-minus-sign" ng-click="remove(parameters.commentTags, $index)"></span>
                    {{ filteredTag.name }}
                </div>
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
                <li id="thirtyDays" ng-class="{ active: parameters.daysOld === 30 }"><a ng-click="setDaysOld(30)">30 days</a></li>
                <li id="sixtyDays" ng-class="{ active: parameters.daysOld === 60 }"><a ng-click="setDaysOld(60)">60 days</a></li>
                <li id="ninetyDays" ng-class="{ active: parameters.daysOld === 90 }"><a ng-click="setDaysOld(90)">90 days</a></li>
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
            <h4>Select Date Range</h4>
            <div class="col-md-6">
                <div id="saveDateRangeSuccessMessage" ng-show="successDateRangeMessage" class="alert alert-success">
                    <button id="closeSaveDateRangeSuccessMessage"
                            class="close"
                            ng-click="successDateRangeMessage = undefined"
                            type="button">&times;</button>
                    {{ successDateRangeMessage }}
                </div>
                <p class="input-group">
                    <select ng-show="savedDateRanges" id="dateFilterSelect" style="width: 135px;margin-bottom:0" ng-model="selectedDateRange" ng-change="selectDateRange(selectedDateRange)"
                            ng-options="dateRange.name for dateRange in savedDateRanges">
                    </select>
                    <span class="input-group-btn">
                        <button tooltip="{{currentDateRange && 'Edit' || 'Save'}} Date Range" type="button" ng-show="showDateRange" class="btn btn-default" ng-click="saveDate()"><i class="icon-edit"></i></button>
                    </span>
                </p>
            </div>
        </div>

        <div class="accordion-inner">
            <h4>Start Date
                <div id="startDateBtnDiv" class="btn-group">
                    <select ng-show="versions" id="startDateVersionItems" style="width: 100px;margin-bottom:0" ng-model="selectedStartVersion" ng-change="selectStartDateVersion(selectedStartVersion)"
                            ng-options="version.name for version in versions">
                    </select>
                </div>
            </h4>
            <div class="col-md-6">
                <p class="input-group">
                    <input id="startDateInput" type="text" class="form-control" style="width:135px;margin-bottom:0" datepicker-popup="dd-MMM-yyyy" ng-model="parameters.startDate"
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
            <h4>End Date
                <div id="endDateBtnDiv" class="btn-group">
                    <select ng-show="versions" id="endDateVersionItems" style="width: 100px;margin-bottom:0" ng-model="selectedEndVersion" ng-change="selectEndDateVersion(selectedEndVersion)"
                            ng-options="version.name for version in versions">
                    </select>
                </div>
            </h4>
            <div class="col-md-6">
                <p class="input-group">
                    <input id="endDateInput" type="text" class="form-control" style="width:135px;margin-bottom:0" datepicker-popup="dd-MMM-yyyy" ng-model="parameters.endDate"
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

<!-- OWASP versions -->
<div class="accordion-group" ng-show="reportId && reportId == OWASP_Report_Id">
    <div class="accordion-heading" ng-click="showOWasp = !showOWasp">
        <span id="showOwasp" class="icon" ng-class="{ 'icon-minus': showOWasp, 'icon-plus': !showOWasp }"></span> OWASP Top 10
    </div>
    <div class="accordion-inner" ng-show="showOWasp">
        <ul class="nav nav-pills">
            <li ng-repeat="owaspVer in OWASP_TOP10" id="owasp{{owaspVer.year}}" ng-class="{ active: parameters.selectedOwasp === owaspVer }"><a ng-click="parameters.selectedOwasp = owaspVer; refresh()">{{owaspVer.year}}</a></li>
        </ul>
    </div>
</div>

<!-- Save Filter -->
<div class="accordion-group">
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

                <div ng-show="trendingActive">
                    <span tooltip="Save the Field Controls and Date Range filters as the default for Trending Report.">
                        <input id="defaultTrendingSelReport" type="checkbox" class="btn"
                               ng-model="parameters.defaultTrending"/>
                        Save Field Controls and Date Range as default for Trending
                    </span>
                    <br>
                </div>

                <br>

                <!-- Save button and save button with spinner. -->
                <a id="saveFilterButton"
                   class="btn btn-primary"
                   style="width:168px"
                   ng-hide="savingFilter"
                   ng-disabled="!currentFilterNameInput"
                   ng-click="saveCurrentFilters()">
                    {{selectedFilter && selectedFilter.id ? 'Update Saved Filter' : 'Save'}}
                </a>
                <button id="savingFilterButton"
                        ng-show="savingFilter"
                        disabled="disabled"
                        class="btn btn-primary">
                    <span class="spinner"></span>
                    {{selectedFilter && selectedFilter.id ? 'Updating' : 'Saving'}}
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Export buttons -->
<security:authorize ifAnyGranted="ROLE_CAN_GENERATE_REPORTS">
    <div class="accordion-group" ng-show="treeTeam || vulnSearch || treeApplication || reportId === 3 || reportId === 11 || reportId === 13">
        <div class="accordion-heading" style="text-align:center">
            <a id="exportCSVButton" ng-click="exportCSV(reportId, DISA_STIG)" class="btn">Export CSV</a>
        </div>
    </div>
    <div class="accordion-group" ng-show="treeTeam || vulnSearch || treeApplication || reportId === 11 || reportId === 13">
        <div class="accordion-heading" style="text-align:center">
            <a id="exportSSVLButton" ng-click="exportSSVL(reportId, DISA_STIG)" class="btn">Export SSVL</a>
        </div>
    </div>

    <div class="accordion-group"  ng-hide="treeTeam || vulnSearch || treeApplication">
        <div class="accordion-heading" style="text-align:center">
                <%--<a id="exportPNGButtonReport" class="btn"--%>
                <%--ng-click="exportPNG()">Export PNG</a>--%>
            <a id="exportPDFButtonReport" class="btn"
               ng-hide="exportingPDF"
               ng-click="exportPDF()">Export PDF</a>
            <button id="exportingPDFButton"
                    ng-show="exportingPDF"
                    disabled="disabled"
                    class="btn btn-primary">
                <span class="spinner"></span>
                Exporting
            </button>
        </div>
    </div>
</security:authorize>
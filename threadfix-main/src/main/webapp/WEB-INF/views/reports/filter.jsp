
<!-- Clear / select all -->
<div class="accordion-group">
    <div class="accordion-heading" style="text-align:center">
        <a id="toggleAllButton" class="btn" ng-click="toggleAllFilters()">
            {{ (showTeamAndApplicationControls || showDetailsControls || showDateControls || showDateRange) ? 'Collapse' : 'Expand' }} All
        </a>
        <a id="clearFiltersButton" class="btn" ng-click="resetFilters()">Clear</a>
    </div>
</div>

<!-- Teams and Applications section (should only show on Reports page -->
<div class="accordion-group" ng-show="!treeApplication && !treeTeam">
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

<!-- Field Controls: Severity, Status -->
<div class="accordion-group">
    <div class="accordion-heading" ng-click="showDetailsControls = !showDetailsControls">
        <span id="showFieldControls" class="icon" ng-class="{ 'icon-minus': showDetailsControls, 'icon-plus': !showDetailsControls }"></span> Field Controls
    </div>
    <div class="filter-group-body" ng-show="showDetailsControls">

        <div class="accordion-inner">
            Severity (In Total)
            <br>
            <div>
                <input id="showInfo" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.info"/>Info<br>
                <input id="showLow" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.low"/>Low<br>
                <input id="showMedium" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.medium"/>Medium<br>
                <input id="showHigh" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.high"/>High<br>
                <input id="showCritical" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.critical"/>Critical
            </div>
        </div>

        <div class="accordion-inner">
            Status (Each Scan)
            <br>
            <div>
                <%--<input id="showOpen" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showOpen"/>Open<br>--%>
                <input id="showClosed" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showClosed"/>Closed<br>
                <input id="showOld" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showOld"/>Old<br>
                <input id="showHidden" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showHidden"/>Hidden<br>
                <input id="showNew" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showNew"/>New<br>
                <input id="showResurfaced" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showResurfaced"/>Resurfaced<br>
            </div>
        </div>

        <div class="accordion-inner">
            Other
            <br>
            <div>
                <input id="showTotal" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showTotal"/>Total<br>
            </div>
        </div>
    </div>
</div>

<!-- Aging -->
<div class="accordion-group">
    <div class="accordion-heading" ng-click="showDateControls = !showDateControls">
        <span id="showDateControls" class="icon" ng-class="{ 'icon-minus': showDateControls, 'icon-plus': !showDateControls }"></span> Aging
    </div>
    <div class="filter-group-body" ng-show="showDateControls">
        <div class="accordion-inner">
            Days Old
            <ul class="nav nav-pills">
                <li id="lastYear" ng-class="{ active: parameters.daysOld === 'LastYear' }"><a ng-click="setDaysOld('LastYear')">Last Year</a></li>
                <li id="lastQuarter" ng-class="{ active: parameters.daysOld === 'LastQuarter' }"><a ng-click="setDaysOld('LastQuarter')">Last Quarter</a></li>
                <li id="forever" ng-class="{ active: parameters.daysOld === 'Forever' }"><a ng-click="setDaysOld('Forever')">Forever</a></li>
            </ul>
        </div>
    </div>
</div>

<!-- Date Range -->
<div class="accordion-group">
    <div class="accordion-heading" ng-click="showDateRange = !showDateRange">
        <span id="showDateRange" class="icon" ng-class="{ 'icon-minus': showDateRange, 'icon-plus': !showDateRange }"></span> Date Range
    </div>
    <div class="filter-group-body" ng-show="showDateRange">
        <div class="accordion-inner">
            <h4>Start Date</h4>
            <div class="col-md-6">
                <p class="input-group">
                    <input id="startDateInput" type="text" class="form-control" ng-model="parameters.startDate" style="width:135px;margin-bottom:0" datepicker-popup="dd-MMMM-yyyy"
                           is-open="startDateOpened" min-date="minDate" max-date="maxDate" date-disabled="disabled(date, mode)" close-text="Close"
                           ng-change="refreshScans()"
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
                    <input id="endDateInput" type="text" class="form-control" ng-model="parameters.endDate" style="width:135px;margin-bottom:0" datepicker-popup="dd-MMMM-yyyy"
                           is-open="endDateOpened" min-date="startDate" max-date="maxDate" date-disabled="disabled(date, mode)" close-text="Close"
                           ng-change="refreshScans()"
                            />
                    <span class="input-group-btn">
                        <button type="button" class="btn btn-default" ng-click="openEndDate($event)"><i class="icon icon-calendar"></i></button>
                    </span>
                </p>
            </div>
        </div>
    </div>
</div>

<!-- Export buttons -->
<security:authorize ifAnyGranted="ROLE_CAN_GENERATE_REPORTS">
    <div class="accordion-group">
        <div class="accordion-heading" style="text-align:center">
            <a id="exportCSVButton" ng-click="exportCSV()" class="btn">Export CSV</a>
        </div>
    </div>
</security:authorize>
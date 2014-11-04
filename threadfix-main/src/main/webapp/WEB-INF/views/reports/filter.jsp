<div ng-controller="ReportFilterController">

<div ng-show="showFilterSections">

<!-- Clear / select all -->
<div class="accordion-group">
    <div class="accordion-heading" style="text-align:center">
        <a id="toggleAllButtonReport" class="btn" ng-click="toggleAllFilters()">
            {{ (showTeamAndApplicationControls || showDetailsControls || showDateControls || showDateRange) ? 'Collapse' : 'Expand' }} All
        </a>
        <a id="clearFiltersButtonReport" class="btn" ng-click="reset()">Clear</a>
    </div>
</div>

<!-- Teams and Applications section -->
<div class="accordion-group">
    <div class="accordion-heading" ng-click="showTeamAndApplicationControls = !showTeamAndApplicationControls">
        <span id="expandTeamAndApplicationFiltersReport" class="icon" ng-class="{ 'icon-minus': showTeamAndApplicationControls, 'icon-plus': !showTeamAndApplicationControls }"></span> Teams And Applications
    </div>
    <div ng-show="showTeamAndApplicationControls" class="filter-group-body">
        <div class="accordion-inner">
            Teams
            <a ng-hide="showTeamInput" ng-click="showTeamInput = !showTeamInput">
                <span id="showTeamInputReport" class="icon" ng-class="{ 'icon-minus': showTeamInput, 'icon-plus': !showTeamInput }"></span>
            </a>
            <br>
            <input id="teamNameTypeaheadReport" focus-on="showTeamInput"
                   ng-show="showTeamInput"
                   typeahead="team.name for team in teams | filter:$viewValue | limitTo:8"
                   type="text"
                   ng-model="newFilteredTeam.name"
                   typeahead-on-select="addNew(parameters.teams, newFilteredTeam.name); newFilteredTeam = {}; showTeamInput = false"/>
            <div ng-repeat="filteredTeam in parameters.teams">
                <span id="removeTeamReport{{ filteredTeam.name }}" class="pointer icon icon-minus-sign" ng-click="remove(parameters.teams, $index)"></span>
                {{ filteredTeam.name }}
            </div>
        </div>

        <div class="accordion-inner">
            Applications
            <a ng-hide="showApplicationInput" ng-click="showApplicationInput = !showApplicationInput">
                <span id="showApplicationInputReport" class="icon" ng-class="{ 'icon-minus': showApplicationInput, 'icon-plus': !showApplicationInput }"></span>
            </a>
            <br>
            <input id="applicationNameTypeaheadReport"
                   focus-on="showApplicationInput"
                   ng-show="showApplicationInput"
                   typeahead="(application.team.name + ' / ' + application.name) for application in searchApplications | filter:$viewValue | limitTo:8"
                   type="text"
                   ng-model="newFilteredApplication.name"
                   typeahead-on-select="addNew(parameters.applications, newFilteredApplication.name); newFilteredApplication = {}; showApplicationInput = false"/>
            <div ng-repeat="filteredApplication in parameters.applications">
                <span id="removeApplicationReport{{ filteredApplication.name }}" class="pointer icon icon-minus-sign" ng-click="remove(parameters.applications, $index)"></span>
                {{ filteredApplication.name }}
            </div>
        </div>
    </div>
</div>

<!-- Field Controls: Severity, Status -->
<div class="accordion-group">
    <div class="accordion-heading" ng-click="showDetailsControls = !showDetailsControls">
        <span id="showFieldControlsReport" class="icon" ng-class="{ 'icon-minus': showDetailsControls, 'icon-plus': !showDetailsControls }"></span> Field Controls
    </div>
    <div class="filter-group-body" ng-show="showDetailsControls">

        <div class="accordion-inner">
            Severity
            <br>
            <div>
                <input id="showInfoReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.info"/>Info<br>
                <input id="showLowReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.low"/>Low<br>
                <input id="showMediumReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.medium"/>Medium<br>
                <input id="showHighReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.high"/>High<br>
                <input id="showCriticalReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.severities.critical"/>Critical
            </div>
        </div>

        <div class="accordion-inner" ng-show="showFullControls">
            Status
            <br>
            <div>
                <%--<input id="showOpen" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showOpen"/>Open<br>--%>
                <input id="showClosedReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showClosed"/>Closed<br>
                <input id="showOldReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showOld"/>Old<br>
                <input id="showHiddenReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showHidden"/>Hidden<br>
                <input id="showNewReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showNew"/>New<br>
                <input id="showResurfacedReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showResurfaced"/>Resurfaced<br>
            </div>
        </div>

        <div class="accordion-inner" ng-show="showFullControls">
            Other
            <br>
            <div>
                <input id="showTotalReport" type="checkbox" class="btn" ng-change="refresh()" ng-model="parameters.showTotal"/>Total<br>
            </div>
        </div>
    </div>
</div>

<!-- Aging -->
<div class="accordion-group" ng-show="showFullControls">
    <div class="accordion-heading" ng-click="showDateControls = !showDateControls">
        <span id="showDateControlsReport" class="icon" ng-class="{ 'icon-minus': showDateControls, 'icon-plus': !showDateControls }"></span> Aging
    </div>
    <div class="filter-group-body" ng-show="showDateControls">
        <div class="accordion-inner">
            Days Old
            <ul class="nav nav-pills">
                <li id="lastYearReport" ng-class="{ active: parameters.daysOldModifier === 'LastYear' }"><a ng-click="setDaysOld('LastYear')">Last Year</a></li>
                <li id="lastQuarterReport" ng-class="{ active: parameters.daysOldModifier === 'LastQuarter' }"><a ng-click="setDaysOld('LastQuarter')">Last Quarter</a></li>
                <li id="foreverReport" ng-class="{ active: parameters.daysOldModifier === 'Forever' }"><a ng-click="setDaysOld('Forever')">Forever</a></li>
            </ul>
        </div>
    </div>
</div>

<!-- Date Range -->
<div class="accordion-group" ng-show="showFullControls">
    <div class="accordion-heading" ng-click="showDateRange = !showDateRange">
        <span id="showDateRangeReport" class="icon" ng-class="{ 'icon-minus': showDateRange, 'icon-plus': !showDateRange }"></span> Date Range
    </div>
    <div class="filter-group-body" ng-show="showDateRange">
        <div class="accordion-inner">
            <h4>Start Date</h4>
            <div class="col-md-6">
                <p class="input-group">
                    <input id="startDateInputReport" type="text" class="form-control" ng-model="parameters.startDate" style="width:135px;margin-bottom:0" datepicker-popup="dd-MMMM-yyyy"
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
                    <input id="endDateInputReport" type="text" class="form-control" ng-model="parameters.endDate" style="width:135px;margin-bottom:0" datepicker-popup="dd-MMMM-yyyy"
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

<!-- Save Filter -->
<div class="accordion-group">
    <div class="accordion-heading" ng-click="showSaveFilter = !showSaveFilter">
        <span id="showSaveFilterReport" class="icon" ng-class="{ 'icon-minus': showSaveFilter, 'icon-plus': !showSaveFilter }"></span> Save Current Filter
    </div>
    <div class="filter-group-body" ng-show="showSaveFilter">
        <div class="accordion-inner">
            <div class="col-md-6">
                <div id="saveFilterSuccessMessageReport" ng-show="saveFilterSuccessMessage" class="alert alert-success">
                    <button id="closeSaveFilterSuccessMessageReport"
                            class="close"
                            ng-click="saveFilterSuccessMessage = undefined"
                            type="button">&times;</button>
                    {{ saveFilterSuccessMessage }}
                </div>
                <div id="saveFilterErrorMessageReport" ng-show="saveFilterErrorMessage" class="alert alert-error">
                    <button id="closeSaveFilterErrorMessageReport"
                            class="close"
                            ng-click="saveFilterErrorMessage = undefined"
                            type="button">&times;</button>
                    {{ saveFilterErrorMessage }}
                </div>
                <input id="filterNameInputReport"
                       ng-maxlength="25"
                       placeholder="Enter a name for the filter"
                       ng-model="currentFilterNameInput"
                       type="text"/>

                <div ng-show="showFullControls">
                    <input id="defaultTrendingSelReport" type="checkbox" class="btn" ng-model="parameters.defaultTrending"/>Default Trending Dashboard Field Controls And Date Range<br>
                </div>

                <br>

                <!-- Save button and save button with spinner. -->
                <a id="saveFilterButtonReport"
                   class="btn btn-primary"
                   style="width:168px"
                   ng-hide="savingFilter"
                   ng-disabled="!currentFilterNameInput"
                   ng-click="saveCurrentFilters()">
                    Save
                </a>
                <button id="savingFilterButtonReport"
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
    <div class="accordion-group"  ng-show="reportId != 3">
        <div class="accordion-heading" style="text-align:center">
            <a id="exportPNGButtonReport" class="btn"
               ng-click="exportPNG()">Export PNG</a>
        </div>
    </div>
</security:authorize>
</div>


<div ng-show="showSavedFilters">
    <!-- Saved Filters section -->
    <div class="saved-filters-tab" ng-show="savedFilters && savedFilters.length > 0">

        <div id="deleteFilterSuccessMessageReport" ng-show="deleteFilterSuccessMessage" class="alert alert-success">
            <button id="closeDeleteFilterSuccessMessageReport"
                    class="close"
                    ng-click="deleteFilterSuccessMessage = undefined"
                    type="button">&times;</button>
            {{ deleteFilterSuccessMessage }}
        </div>

        <select id="filterSelectReport" style="width: 220px;" ng-model="selectedFilter" ng-change="loadFilter(selectedFilter)"
                ng-options="(filter.defaultTrending?filter.name+'*':filter.name) for filter in savedFilters">
            <option>Select a Filter</option>
        </select>

        <div ng-show="savedFilters && savedFilters.length > 0">
            <hr>

            <!-- Delete button and delete button with spinner. -->
            <a id="deleteFilterButtonReport"
               class="btn btn-danger"
               ng-disabled="!selectedFilter"
               ng-click="deleteCurrentFilter()">
                Delete Selected Filter
            </a>
            <button id="deletingFilterButtonReport"
                    ng-show="deletingFilter"
                    disabled="disabled"
                    class="btn btn-primary">
                <span class="spinner"></span>
                Deleting
            </button>

            <a id="clearFiltersButtonSavedTabReport"
               class="btn"
               ng-disabled="!selectedFilter"
               ng-click="resetFiltersIfEnabled()">
                Clear Filter
            </a>
        </div>
    </div>
</div>
</div>

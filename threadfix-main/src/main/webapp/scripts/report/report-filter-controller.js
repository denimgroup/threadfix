var module = angular.module('threadfix');

module.controller('ReportFilterController', function($http, $scope, $rootScope, filterService, vulnSearchParameterService, tfEncoder, reportExporter, $log) {

    $scope.parameters = undefined;

    $scope.resetFiltersIfEnabled = function() {
        if ($scope.selectedFilter) {
            $scope.reset();
        }
    };

    $scope.reset = function() {
        $scope.$parent.resetFilters();
        $scope.parameters = $scope.$parent.parameters;
        $scope.selectedFilter = $scope.$parent.savedDefaultTrendingFilter ? $scope.$parent.savedDefaultTrendingFilter : undefined;
        if ($scope.selectedFilter)
            $scope.currentFilterNameInput = $scope.selectedFilter;
        else
            $scope.currentFilterNameInput = null;
        $rootScope.$broadcast("resetParameters", $scope.parameters)
    };

    $scope.$on('loadTrendingReport', function() {
        if (!$scope.parameters) {
            $scope.$parent.resetFilters();
            $scope.parameters = $scope.$parent.parameters;
        }
        $scope.showFullControls = true;

    });

    $scope.$on('loadComparisonReport', function() {
        if (!$scope.parameters) {
            $scope.$parent.resetFilters();
            $scope.parameters = $scope.$parent.parameters;
        }

        $scope.showFullControls = false;

    });

    $scope.$on('loadSnapshotReport', function() {

        if (!$scope.parameters) {
            $scope.$parent.resetFilters();
            $scope.parameters = $scope.$parent.parameters;
        }

        $scope.showFullControls = false;
    });

    $scope.toggleAllFilters = function() {
        if ($scope.showTeamAndApplicationControls
            || $scope.showSaveFilter
            || $scope.showDetailsControls
            || $scope.showDateControls
            || $scope.showDateRange
            || $scope.showTypeAndMergedControls
            || $scope.showTagControls
            || $scope.showOWasp) {
            $scope.showTeamAndApplicationControls = false;
            $scope.showDetailsControls = false;
            $scope.showDateControls = false;
            $scope.showDateRange = false;
            $scope.showSaveFilter = false;
            $scope.showTypeAndMergedControls = false;
            $scope.showTagControls = false;
            $scope.showOWasp = false;
        } else {
            $scope.showTeamAndApplicationControls = true;
            $scope.showDetailsControls = true;
            $scope.showDateControls = true;
            $scope.showDateRange = true;
            $scope.showSaveFilter = true;
            $scope.showTypeAndMergedControls = true;
            $scope.showTagControls = true;
            $scope.showOWasp = true;
        }
    };

    $scope.maxDate = new Date();

    $scope.openEndDate = function($event) {
        resetAging();
        $event.preventDefault();
        $event.stopPropagation();

        $scope.endDateOpened = true;
    };

    $scope.openStartDate = function($event) {
        resetAging();
        $event.preventDefault();
        $event.stopPropagation();

        $scope.startDateOpened = true;
    };

    var resetAging = function() {
        $scope.parameters.daysOldModifier = undefined;
        $scope.parameters.daysOld = undefined;
    };


    $scope.refreshScans = function(){
        $rootScope.$broadcast("resetParameters", $scope.parameters);
    };

    $scope.refresh = function() {
        $rootScope.$broadcast("updateDisplayData", $scope.parameters);
    };

    $scope.$on('updateBackParameters', function(event, parameters) {
        $scope.parameters = angular.copy(parameters);
    });

    $scope.addNew = function(collection, name) {
        var found = false;

        collection.forEach(function(item) {
            if (item && item.name === name) {
                found = true;
            }
        });

        if (!found) {
            collection.push({name: name});

            $rootScope.$broadcast("resetParameters", $scope.parameters);

        }
    };

    $scope.remove = function(collection, index) {
        collection.splice(index, 1);

        $rootScope.$broadcast("resetParameters", $scope.parameters);

    };

    $scope.setDaysOldModifier = function(modifier) {
        resetDateRange();
        if ($scope.parameters.daysOldModifier === modifier) {
            $scope.parameters.daysOldModifier = undefined;
            $rootScope.$broadcast("resetParameters", $scope.parameters);
        } else {
            $scope.parameters.daysOldModifier = modifier;
            if ($scope.parameters.daysOld || modifier === 'LastYear' || modifier === 'LastQuarter' || modifier === 'Forever') {
                $rootScope.$broadcast("resetParameters", $scope.parameters);
            }
        }
    };

    $scope.setDaysOld = function(days) {
        resetDateRange();
        if ($scope.parameters.daysOld === days) {
            $scope.parameters.daysOld = undefined;
            $rootScope.$broadcast("resetParameters", $scope.parameters);
        } else {
            $scope.parameters.daysOld = days;
            if ($scope.parameters.daysOldModifier) {
                $rootScope.$broadcast("resetParameters", $scope.parameters);
            }
        }
    };

    $scope.setNumberMerged = function(numberMerged) {
        if ($scope.parameters.numberMerged === numberMerged) {
            $scope.parameters.numberMerged = undefined;
            $rootScope.$broadcast("resetParameters", $scope.parameters);
        } else {
            $scope.parameters.numberMerged = numberMerged;
            $rootScope.$broadcast("resetParameters", $scope.parameters);
        }
    };

    $scope.deleteCurrentFilter = function() {
        filterService.deleteCurrentFilter($scope, filterSavedFilters);
    };

    $scope.loadFilter = function(filter) {

        $scope.selectedFilter = filter;
        $scope.parameters = JSON.parse($scope.selectedFilter.json);
        $scope.currentFilterNameInput = filter.name;

        if ($scope.parameters.selectedOwasp
            && $scope.$parent.OWASP_TOP10) {
            $scope.$parent.OWASP_TOP10.forEach(function(owasp, index){
                if (owasp.year === $scope.parameters.selectedOwasp.year)
                    $scope.parameters.selectedOwasp = $scope.$parent.OWASP_TOP10[index];
            });
        }

        if (!filter.defaultTrending) {
            $scope.parameters.defaultTrending = false;
        }
        if ($scope.parameters.startDate)
            $scope.parameters.startDate = new Date($scope.parameters.startDate);
        if ($scope.parameters.endDate)
            $scope.parameters.endDate = new Date($scope.parameters.endDate);

        $rootScope.$broadcast("resetParameters", $scope.parameters);

    };

    $scope.copyCurrentFilter = function() {

        $scope.currentFilterNameInput = $scope.selectedFilter.name + '~copy';
        $scope.selectedFilter = undefined;

    };

    $scope.togglePermission = function(name) {

        if (!$scope.parameters.permissionsList) {
            $scope.parameters.permissionsList = [];
        }

        var index = $scope.parameters.permissionsList.indexOf(name);

        if (index === -1) {
            $scope.parameters.permissionsList.push(name);
        } else {
            $scope.remove($scope.parameters.permissionsList, index);
        }

        $scope.refresh();

    };

    $scope.saveCurrentFilters = function() {
        if ($scope.$parent.trendingActive)
            $scope.parameters.filterType = {isTrendingFilter : true};
        else if ($scope.$parent.snapshotActive)
            $scope.parameters.filterType = {isSnapshotFilter : true};
        else if ($scope.$parent.complianceActive)
            $scope.parameters.filterType = {isComplianceFilter : true};
        else
            $scope.parameters.filterType = {isVulnSearchFilter : true};

        filterService.saveCurrentFilters($scope, filterSavedFilters);

    };

    var filterSavedFilters = function(filter){
        var parameters = JSON.parse(filter.json);
        if (!parameters.filterType)
            return false;
        else {
            if ($scope.$parent.snapshotActive)
                return (parameters.filterType.isSnapshotFilter);
            else if ($scope.$parent.trendingActive)
                return (parameters.filterType.isTrendingFilter);
            else if ($scope.$parent.complianceActive)
                return (parameters.filterType.isComplianceFilter);
            else
                return (!parameters.filterType || parameters.filterType.isVulnSearchFilter);
        }
    };

    var resetDateRange = function(){
        // Reset Date Range
        $scope.parameters.startDate = null;
        $scope.startDateOpened = false;
        $scope.parameters.endDate = null;
        $scope.endDateOpened = false;
    };

    $scope.exportCSV = function(reportId, DISA_STIG) {

        if (reportId === 3) {
            // Progress By Vulnerability report
            $scope.$parent.exportCSV();
        } else {
            $log.info('Downloading vulnerabilities list');

            var parameters = angular.copy($scope.parameters);

            vulnSearchParameterService.updateParameters($scope, parameters);

            // OWASP TOP 10 report
            if (reportId === 11 && parameters.selectedOwasp) {
                parameters.genericVulnerabilities = [];
                parameters.selectedOwasp.top10.forEach(function(owaspVuln){
                    owaspVuln.members.forEach(function(cweId){
                        parameters.genericVulnerabilities.push({id: cweId})

                    });
                });
            }

            // DISA STIG report
            if (reportId === 13) {
                parameters.genericVulnerabilities = [];
                DISA_STIG.forEach(function(cat){
                    cat.members.forEach(function(stig){
                        stig.cweIds.forEach(function(cweId){
                            parameters.genericVulnerabilities.push({id: cweId});
                        });
                    });
                });
            }

            if (reportExporter.checkOldIE()) {
                window.location.href = tfEncoder.encode("/reports/search/export/csv");
            } else {
                $http.post(tfEncoder.encode("/reports/search/export/csv"), parameters).
                    success(function(data, status, headers, config, response)
                    {
                        reportExporter.exportCSV(data, "application/octet-stream", "search_export.csv");
                    }).
                    error(function(data, status, headers, config) {
                        $scope.errorMessage = "Failed to retrieve vulnerability report. HTTP status was " + status;
                        $scope.loadingTree = false;
                    });
            }
        }
    };

});

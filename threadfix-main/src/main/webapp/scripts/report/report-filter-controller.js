var module = angular.module('threadfix');

module.controller('ReportFilterController', function($http, $scope, $rootScope, filterService, vulnSearchParameterService, tfEncoder, reportExporter) {

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
            || $scope.showTagControls) {
            $scope.showTeamAndApplicationControls = false;
            $scope.showDetailsControls = false;
            $scope.showDateControls = false;
            $scope.showDateRange = false;
            $scope.showSaveFilter = false;
            $scope.showTypeAndMergedControls = false;
            $scope.showTagControls = false;
        } else {
            $scope.showTeamAndApplicationControls = true;
            $scope.showDetailsControls = true;
            $scope.showDateControls = true;
            $scope.showDateRange = true;
            $scope.showSaveFilter = true;
            $scope.showTypeAndMergedControls = true;
            $scope.showTagControls = true;
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
        if (!filter.defaultTrending) {
            $scope.parameters.defaultTrending = false;
        }
        if ($scope.parameters.startDate)
            $scope.parameters.startDate = new Date($scope.parameters.startDate);
        if ($scope.parameters.endDate)
            $scope.parameters.endDate = new Date($scope.parameters.endDate);

        $rootScope.$broadcast("resetParameters", $scope.parameters);
//        $scope.currentFilterNameInput = $scope.selectedFilter.name;
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
    }

    var resetDateRange = function(){
        // Reset Date Range
        $scope.parameters.startDate = null;
        $scope.startDateOpened = false;
        $scope.parameters.endDate = null;
        $scope.endDateOpened = false;
    };

    $scope.exportCSV = function(reportId) {

        if (reportId === 3) {
            $scope.$parent.exportCSV();
        } else {
            console.log('Downloading vulnerabilities list');

            var parameters = angular.copy($scope.parameters);

            vulnSearchParameterService.updateParameters($scope, parameters);

            $http.post(tfEncoder.encode("/reports/search/export/csv"), parameters).
                success(function(data, status, headers, config, response) {

                    var octetStreamMime = "application/octet-stream";

                    // Get the headers
                    headers = headers();

                    // Get the filename from the x-filename header or default to "download.bin"
                    var filename = headers["x-filename"] || "search_export.csv";

                    // Determine the content type from the header or default to "application/octet-stream"
                    var contentType = headers["content-type"] || octetStreamMime;

                    if(navigator.msSaveBlob)
                    {
                        // Save blob is supported, so get the blob as it's contentType and call save.
                        var blob = new Blob([data], { type: contentType });
                        navigator.msSaveBlob(blob, filename);
                        console.log("SaveBlob Success");
                    }
                    else {
                        reportExporter.exportCSV(data, contentType, filename);
                    }
                }).
                error(function(data, status, headers, config) {
                    $scope.errorMessage = "Failed to retrieve vulnerability report. HTTP status was " + status;
                    $scope.loadingTree = false;
                });
        };
    }

});

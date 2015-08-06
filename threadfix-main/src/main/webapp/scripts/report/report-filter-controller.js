var module = angular.module('threadfix');

module.controller('ReportFilterController', function($http, $scope, $rootScope, filterService, vulnSearchParameterService, tfEncoder, reportExporter, $log, $modal, threadFixModalService) {

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
            || $scope.showOWasp
            || $scope.showPermissions) {
            toggleAll(false);
        } else {
            toggleAll(true);
        }
    };

    var toggleAll = function(bool){
        $scope.showTeamAndApplicationControls = bool;
        $scope.showDetailsControls = bool;
        $scope.showDateControls = bool;
        $scope.showDateRange = bool;
        $scope.showSaveFilter = bool;
        $scope.showTypeAndMergedControls = bool;
        $scope.showTagControls = bool;
        $scope.showOWasp = bool;
        $scope.showPermissions = bool;
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
        var reportName = "search_export.csv";

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
                reportName = "owasp_top_10_report.csv"
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
                reportName = "disa_stig_report.csv"
            }

            if (reportExporter.checkOldIE()) {
                window.location.href = tfEncoder.encode("/reports/search/export/csv");
            } else {
                $http.post(tfEncoder.encode("/reports/search/export/csv"), parameters).
                    success(function(data, status, headers, config, response)
                    {
                        reportExporter.exportCSV(data, "application/octet-stream", reportName);
                    }).
                    error(function(data, status, headers, config) {
                        $scope.errorMessage = "Failed to retrieve vulnerability report. HTTP status was " + status;
                        $scope.loadingTree = false;
                    });
            }
        }
    };

    $scope.saveDate = function() {
        var modalInstance = $modal.open({
            templateUrl: 'newDateModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/reports/filter/saveDateRange");
                },
                object: function() {

                    var date, startDate, endDate;

                    if ($scope.parameters.endDate) {
                        date = new Date($scope.parameters.endDate);
                        if (date) {
                            endDate = date.getTime();
                        }
                    }
                    if ($scope.parameters.startDate) {
                        date = new Date($scope.parameters.startDate);
                        if (date) {
                            startDate = date.getTime();
                        }
                    }

                    return {
                        startDate: startDate,
                        endDate: endDate,
                        id: $scope.currentDateRange ? $scope.currentDateRange.id : undefined,
                        name: $scope.currentDateRange ? $scope.currentDateRange.name : undefined
                    };
                },
                config: function() {
                    return {
                        label: $scope.currentDateRange ? "Edit Date Range" : "New Date Range"
                    };
                },
                buttonText: function() {
                    return "Save Date";
                },
                deleteUrl: function() {
                    return $scope.currentDateRange ? tfEncoder.encode("/reports/filter/dateRange/" + $scope.currentDateRange.id + "/delete") : undefined;
                }
            }

        });

        modalInstance.result.then(function (newDateRange) {
            if (newDateRange) {

                if ($scope.currentDateRange) {
                    deleteElement($scope.savedDateRanges, $scope.selectedDateRange);
                    $scope.successDateRangeMessage = "Edited date range " + newDateRange.name;
                } else {
                    $scope.successDateRangeMessage = "Saved date range " + newDateRange.name;
                }

                threadFixModalService.addElement($scope.savedDateRanges, newDateRange);
                $scope.savedDateRanges.sort(nameCompare);
                $scope.currentDateRange = newDateRange;
                $scope.selectedDateRange = newDateRange;
            } else {
                $scope.successDateRangeMessage = "Deleted date range " + $scope.currentDateRange.name;
                deleteElement($scope.savedDateRanges, $scope.selectedDateRange);
                $scope.currentDateRange = undefined;
                $scope.selectedDateRange = undefined;

            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    var deleteElement = function(collection, element) {
        var index = getIndex(collection, element);
        if (index > -1) {
            collection.splice(index, 1);
        }

        if (collection.length === 0) {
            collection = undefined;
        }
    };

    var getIndex = function(collection, element) {
        var index = -1;

        if (collection) {
            collection.some(function(e, i){
                if (e.id == element.id) {
                    index = i;
                    return true;
                }
            });
        }

        return index;
    };

    $scope.selectDateRange = function(selectedDateRange) {
        if (!selectedDateRange.id) {
            resetAging();
            $scope.currentDateRange = undefined;
            $scope.parameters.startDate = undefined;
            $scope.parameters.endDate = undefined;
        } else {
            resetAging();
            $scope.currentDateRange = selectedDateRange;
            $scope.parameters.startDate = $scope.currentDateRange.startDate;
            $scope.parameters.endDate = $scope.currentDateRange.endDate;
        }
        $scope.refresh();
    };

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

});

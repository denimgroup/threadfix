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
        storeCurrentFilter();
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
        storeCurrentFilter();
        $rootScope.$broadcast("resetParameters", $scope.parameters);
    };

    $scope.refresh = function() {
        storeCurrentFilter();
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

            storeCurrentFilter();
            $rootScope.$broadcast("resetParameters", $scope.parameters);

        }
    };

    $scope.addNewObject = function(collection, obj) {
        var found = false;

        collection.forEach(function(item) {
            if (item && item.id === obj.id) {
                found = true;
            }
        });

        if (!found) {
            collection.push(obj);
            storeCurrentFilter();
            $rootScope.$broadcast("resetParameters", $scope.parameters);
        }
    };

    $scope.remove = function(collection, index) {
        collection.splice(index, 1);

        storeCurrentFilter();
        $rootScope.$broadcast("resetParameters", $scope.parameters);

    };

    $scope.setDaysOldModifier = function(modifier) {
        resetDateRange();
        if ($scope.parameters.daysOldModifier === modifier) {
            $scope.parameters.daysOldModifier = undefined;
            storeCurrentFilter();
            $rootScope.$broadcast("resetParameters", $scope.parameters);
        } else {
            $scope.parameters.daysOldModifier = modifier;
            if ($scope.parameters.daysOld || modifier === 'LastYear' || modifier === 'LastQuarter' || modifier === 'Forever') {
                storeCurrentFilter();
                $rootScope.$broadcast("resetParameters", $scope.parameters);
            }
        }
    };

    $scope.setDaysOld = function(days) {
        resetDateRange();
        if ($scope.parameters.daysOld === days) {
            $scope.parameters.daysOld = undefined;
            storeCurrentFilter();
            $rootScope.$broadcast("resetParameters", $scope.parameters);
        } else {
            $scope.parameters.daysOld = days;
            if ($scope.parameters.daysOldModifier) {
                storeCurrentFilter();
                $rootScope.$broadcast("resetParameters", $scope.parameters);
            }
        }
    };

    $scope.setNumberMerged = function(numberMerged) {
        if ($scope.parameters.numberMerged === numberMerged) {
            $scope.parameters.numberMerged = undefined;
            storeCurrentFilter();
            $rootScope.$broadcast("resetParameters", $scope.parameters);
        } else {
            $scope.parameters.numberMerged = numberMerged;
            storeCurrentFilter();
            $rootScope.$broadcast("resetParameters", $scope.parameters);
        }
    };

    $scope.deleteCurrentFilter = function() {
        filterService.deleteCurrentFilter($scope, function() {
            storeCurrentFilter();
        });
    };

    var storeCurrentFilter = function() {
        if ($scope.storeFiltersInLocalStorage) {
            filterService.storeCurrentFilter($scope);
        }
    };

    var loadCurrentFilter = function() {
        if ($scope.storeFiltersInLocalStorage) {
            var currentFilter = filterService.loadCurrentFilter($scope);
            if (currentFilter) {
                var foundFilterId = false;
                if (currentFilter.id && $scope.savedFilters) {
                    for (var savedFilterIndex in $scope.savedFilters) {
                        var savedFilter = $scope.savedFilters[savedFilterIndex];
                        if (currentFilter.id == savedFilter.id) {
                            foundFilterId = true;
                            break;
                        }
                    }
                }
                if (!foundFilterId) {
                    currentFilter.id = undefined;
                }
                $scope.loadFilter(currentFilter);
            }
        }
    };

    $scope.$on('loadCurrentFilter', function() {
        loadCurrentFilter();
    });

    $scope.loadFilter = function(filter) {
        $scope.$parent.resetFilters();
        $scope.parameters = $scope.$parent.parameters;

        $scope.selectedFilter = filter;
        var filterParameters = JSON.parse($scope.selectedFilter.json);

        for (var key in $scope.parameters) {
            if (filterParameters.hasOwnProperty(key)) {
                $scope.parameters[key] = filterParameters[key];
            }
        }

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

        storeCurrentFilter();
        $rootScope.$broadcast("resetParameters", $scope.parameters);

    };

    $scope.copyCurrentFilter = function() {

        $scope.currentFilterNameInput = $scope.selectedFilter.name + '~copy';
        $scope.selectedFilter = undefined;
        storeCurrentFilter();

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
        filterService.saveCurrentFilters($scope, function() {
            storeCurrentFilter();
        });
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
            exportTextFile(reportId, DISA_STIG, "/reports/search/export/csv", "csv");
        }
    };

    $scope.exportSSVL = function(reportId, DISA_STIG) {
        exportTextFile(reportId, DISA_STIG, "/reports/search/export/ssvl", "ssvl");
    };

    var exportTextFile = function(reportId, DISA_STIG, url, extension) {
        var reportName = "search_export." + extension;

        $log.info('Downloading vulnerabilities list in ' + extension + ' format');

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
            reportName = "owasp_top_10_report." + extension;
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
            reportName = "disa_stig_report." + extension;
        }

        if (reportExporter.checkOldIE()) {
            window.location.href = tfEncoder.encode(url);
        } else {
            reportExporter.downloadFileByForm(tfEncoder.encode(url), parameters, "post");
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

    $scope.selectStartDateVersion = function(version) {
        resetAging();
        $scope.parameters.startDate = version.date;
        $scope.refresh();
    }

    $scope.selectEndDateVersion = function(version) {
        resetAging();
        $scope.parameters.endDate = version.date;
        $scope.refresh();
    }

    /*
    For application detail page
     */
    $scope.$on("versionsChange", function(event, versions){
        $scope.versions = angular.copy(versions);
        if ($scope.versions) {
            $scope.versions.unshift({date: undefined, name: 'Version'});
            $scope.selectedStartVersion = $scope.versions[0];
            $scope.selectedEndVersion = $scope.versions[0];
        }
    });

    $scope.$watch('parameters', function(){
        if ($scope.parameters && !$scope.appId) { // In team detail page and analytics vuln search
            if ($scope.parameters.tags && $scope.parameters.tags.length > 0)
                $scope.versions = undefined;

            else if ($scope.parameters.teams && $scope.parameters.teams.length > 0)
                $scope.versions = undefined;

            else if (!$scope.parameters.applications || $scope.parameters.applications.length !== 1) {
                $scope.versions = undefined;
            } else {
                if ($scope.versionsMap) {
                    $scope.versions = angular.copy($scope.versionsMap[$scope.parameters.applications[0].name]);
                    if ($scope.versions) {
                        $scope.versions.unshift({date:undefined, name: 'Version'});
                        $scope.selectedStartVersion = $scope.versions[0];
                        $scope.selectedEndVersion = $scope.versions[0];
                    }
                } else {
                    $scope.versions = undefined;
                }
            }
        }
    });

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

});

var module = angular.module('threadfix');

module.controller('VulnSearchController', function($scope, $http, tfEncoder, vulnSearchParameterService, vulnTreeTransformer) {
    $scope.parameters = {
        teams: [],
        applications: [],
        scanners: [],
        genericVulnerabilities: [],
        severities: [],
        numberVulnerabilities: 10,
        showOpen: true,
        showClosed: false,
        showFalsePositive: false,
        showHidden: false
    };

    $scope.$watch(function() { return $scope.parameters; }, $scope.refresh, true);

    $scope.maxDate = new Date();

    $scope.openEndDate = function($event) {
        $event.preventDefault();
        $event.stopPropagation();

        $scope.endDateOpened = true;
    };

    $scope.openStartDate = function($event) {
        $event.preventDefault();
        $event.stopPropagation();

        $scope.startDateOpened = true;
    };

    $scope.$on('loadVulnerabilitySearchTable', function(event) {
        $scope.refresh();
    });

    $scope.refresh = function() {
        $scope.loading = true;
        vulnSearchParameterService.updateParameters($scope, $scope.parameters);
        $http.post(tfEncoder.encode("/reports/search"), $scope.parameters).
            success(function(data, status, headers, config) {
                $scope.initialized = true;

                if (data.success) {
                    $scope.vulns = data.object.vulns;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loading = false;
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                $scope.loading = false;
            });

        $http.post(tfEncoder.encode("/reports/tree"), $scope.parameters).
            success(function(data, status, headers, config) {
                $scope.initialized = true;

                if (data.success) {
                    $scope.vulnTree = vulnTreeTransformer.transform(data.object);
                    $scope.badgeWidth = 0;

                    if ($scope.vulnTree) {
                        $scope.vulnTree.forEach(function(treeElement) {
                            var size = 7;
                            var test = treeElement.total;
                            while (test >= 10) {
                                size = size + 7;
                                test = test / 10;
                            }

                            if (size > $scope.badgeWidth) {
                                $scope.badgeWidth = size;
                            }
                        });
                    }

                    $scope.badgeWidth = { "text-align": "right", width: $scope.badgeWidth + 'px' };

                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loading = false;
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                $scope.loading = false;
            });
    }

    $scope.add = function(collection) {
        collection.push({ name: '' })
    }

    $scope.addNew = function(collection, name) {
        var found = false;

        collection.forEach(function(item) {
            if (item && item.name === name) {
                found = true;
            }
        });

        if (!found) {
            collection.push({name: name});
            $scope.refresh();
        }
    };

    $scope.remove = function(collection, index) {
        collection.splice(index, 1);
        $scope.refresh();
    }

    $scope.setNumberVulnerabilities = function(number) {
        $scope.parameters.numberVulnerabilities = number;
        $scope.refresh();
    }

    $scope.setDaysOldModifier = function(modifier) {
        if ($scope.parameters.daysOldModifier === modifier) {
            $scope.parameters.daysOldModifier = undefined;
            $scope.refresh();
        } else {
            $scope.parameters.daysOldModifier = modifier;
            if ($scope.parameters.daysOld) {
                $scope.refresh();
            }
        }
    }

    $scope.setDaysOld = function(days) {
        if ($scope.parameters.daysOld === days) {
            $scope.parameters.daysOld = undefined;
            $scope.refresh();
        } else {
            $scope.parameters.daysOld = days;
            if ($scope.parameters.daysOldModifier) {
                $scope.refresh();
            }
        }
    }

    $scope.setNumberMerged = function(numberMerged) {
        if ($scope.parameters.numberMerged === numberMerged) {
            $scope.parameters.numberMerged = undefined;
            $scope.refresh();
        } else {
            $scope.parameters.numberMerged = numberMerged;
            $scope.refresh();
        }
    }

    $scope.expandAndRetrieveTable = function(element) {
        $scope.updateElementTable(element, 10, 1);
    }

    $scope.deleteFilter = function() {
        $http.post(tfEncoder.encode("/reports/filter/delete/" + $scope.selectedFilter.id)).
            success(function(data, status, headers, config) {
                console.log("Successfully deleted filter.");
                $scope.initialized = true;

                if (data.success) {
                    $scope.selectedFilter = undefined;
                    $scope.savedFilters = data.object;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loading = false;
            }).
            error(function(data, status, headers, config) {
                console.log("Failed to save filters.");
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                $scope.loading = false;
            });
    }

    $scope.loadFilter = function() {
        $scope.parameters = JSON.parse($scope.selectedFilter.json);
        $scope.refresh();
    }

    $scope.saveCurrentFilters = function() {
        console.log("Saving filters");

        var submissionObject = vulnSearchParameterService.serialize($scope, $scope.parameters);

        submissionObject.name = $scope.currentFilterNameInput;

        $http.post(tfEncoder.encode("/reports/filter/save"), submissionObject).
            success(function(data, status, headers, config) {
                console.log("Successfully saved filters.");
                $scope.initialized = true;

                if (data.success) {
                    $scope.savedFilters = data.object;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loading = false;
            }).
            error(function(data, status, headers, config) {
                console.log("Failed to save filters.");
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                $scope.loading = false;
            });
    }

    $scope.updateElementTable = function(element, numToShow, page) {
        console.log('Updating element table');

        var parameters = angular.copy($scope.parameters);

        vulnSearchParameterService.updateParameters($scope, parameters);
        parameters.genericSeverities.push({ intValue: element.intValue });
        parameters.genericVulnerabilities = [ element.genericVulnerability ];
        parameters.page = page;
        parameters.numberVulnerabilities = numToShow;

        $http.post(tfEncoder.encode("/reports/search"), parameters).
            success(function(data, status, headers, config) {
                $scope.initialized = true;

                element.expanded = true;

                if (data.success) {
                    element.vulns = data.object.vulns;
                    element.totalVulns = data.object.vulnCount;
                    element.max = Math.ceil(data.object.vulnCount/100);
                    element.numberToShow = numToShow;
                    element.page = page;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loading = false;
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                $scope.loading = false;
            });
    }
});

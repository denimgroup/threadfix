var module = angular.module('threadfix');

module.controller('VulnSearchController', function($scope, $window, $http, tfEncoder, $modal, $log, vulnSearchParameterService, vulnTreeTransformer) {
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

    var refreshVulnTable = function(parameters) {
        $http.post(tfEncoder.encode("/reports/search"), parameters).
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
    }

    var refreshVulnTree = function(parameters) {
        $scope.loadingTree = true;

        $http.post(tfEncoder.encode("/reports/tree"), parameters).
            success(function(data, status, headers, config) {
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

                $scope.loadingTree = false;
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                $scope.loadingTree = false;
            });
    }

    $scope.refresh = function() {
        $scope.loading = true;
        vulnSearchParameterService.updateParameters($scope, $scope.parameters);
        refreshVulnTable($scope.parameters);
        refreshVulnTree($scope.parameters);
        $scope.lastLoadedFilterName = undefined;
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
                    $scope.deleteFilterSuccessMessage = "Successfully deleted filter " + $scope.selectedFilter.name;
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
        $scope.lastLoadedFilterName = $scope.selectedFilter.name;
    }

    $scope.saveCurrentFilters = function() {
        console.log("Saving filters");

        if ($scope.currentFilterNameInput) {
            $scope.savingFilter = true;

            var submissionObject = vulnSearchParameterService.serialize($scope, $scope.parameters);

            submissionObject.name = $scope.currentFilterNameInput;

            $http.post(tfEncoder.encode("/reports/filter/save"), submissionObject).
                success(function(data, status, headers, config) {
                    console.log("Successfully saved filters.");
                    $scope.savingFilter = false;

                    if (data.success) {
                        $scope.savedFilters = data.object;
                        $scope.currentFilterNameInput = '';
                        $scope.saveFilterSuccessMessage = 'Successfully saved filter ' + submissionObject.name;
                    } else {
                        $scope.saveFilterErrorMessage = "Failure. Message was : " + data.message;
                    }

                }).
                error(function(data, status, headers, config) {
                    console.log("Failed to save filters.");
                    $scope.saveFilterErrorMessage = "Failed to save team. HTTP status was " + status;
                    $scope.savingFilter = false;
                });
        }
    }

    // collapse duplicates: [arachni, arachni, appscan] => [arachni (2), appscan]
    var updateChannelNames = function(vulnerability) {
        if (vulnerability.channelNames.length > 1 ) {
            var holder = {};
            vulnerability.channelNames.forEach(function(name) {
                if (holder[name]) {
                    holder[name] = holder[name] + 1;
                } else {
                    holder[name] = 1;
                }
            });

            vulnerability.channelNames = [];
            for (var key in holder) {
                if (holder.hasOwnProperty(key)){
                    if (holder[key] === 1) {
                        vulnerability.channelNames.push(key)
                    } else {
                        vulnerability.channelNames.push(key + " (" + holder[key] + ")")
                    }
                }
            }
        }
    }

    $scope.updateElementTable = function(element, numToShow, page) {
        console.log('Updating element table');

        var parameters = angular.copy($scope.parameters);

        vulnSearchParameterService.updateParameters($scope, parameters);
        parameters.genericSeverities.push({ intValue: element.intValue });
        parameters.genericVulnerabilities = [ element.genericVulnerability ];
        parameters.page = page;
        parameters.numberVulnerabilities = numToShow;

        $scope.loadingTree = true;

        $http.post(tfEncoder.encode("/reports/search"), parameters).
            success(function(data, status, headers, config) {
                element.expanded = true;

                if (data.success) {
                    element.vulns = data.object.vulns;
                    element.vulns.forEach(updateChannelNames)
                    element.totalVulns = data.object.vulnCount;
                    element.max = Math.ceil(data.object.vulnCount/100);
                    element.numberToShow = numToShow;
                    element.page = page;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loadingTree = false;
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                $scope.loadingTree = false;
            });
    }

    $scope.goTo = function(vuln) {
        $window.location.href = tfEncoder.encode($scope.getUrlBase(vuln));
    };

    $scope.getUrlBase = function(vuln) {
        return "/organizations/" + vuln.team.id + "/applications/" + vuln.app.id + "/vulnerabilities/" + vuln.id;
    };

    $scope.showCommentForm = function(vuln) {
        var modalInstance = $modal.open({
            templateUrl: 'vulnCommentForm.html',
            controller: 'GenericModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode($scope.getUrlBase(vuln) + "/addComment");
                },
                object: function () {
                    return {};
                },
                buttonText: function() {
                    return "Add Comment";
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (comments) {
            vuln.vulnerabilityComments = comments
            $log.info("Successfully added comment.");
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.getDocumentUrl = function(vulnerability, document) {
        return tfEncoder.encode($scope.getUrlBase(vulnerability) + "/documents/" + document.id + "/view");
    }
});

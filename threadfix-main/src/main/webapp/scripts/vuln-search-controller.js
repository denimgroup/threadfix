var module = angular.module('threadfix');

module.controller('VulnSearchController', function($scope, $rootScope, $window, $http, tfEncoder, $modal, $log, vulnSearchParameterService, vulnTreeTransformer, threadfixAPIService) {

    $scope.parameters = {};

    $scope.loadingTree = true;

    $scope.resetFiltersIfEnabled = function() {
        if ($scope.selectedFilter) {
            $scope.resetFilters();
        }
    };

    $scope.resetFilters = function() {
        $scope.parameters = {
            teams: [],
            applications: [],
            scanners: [],
            genericVulnerabilities: [],
            severities: {},
            numberVulnerabilities: 10,
            showOpen: true,
            showClosed: false,
            showFalsePositive: false,
            showHidden: false
        };

        $scope.endDate = undefined;
        $scope.selectedFilter = undefined;
        $scope.startDate = undefined;

        $scope.refresh();
    };

    $scope.toggleAllFilters = function() {
        if ($scope.showSaveAndLoadControls || $scope.showTeamAndApplicationControls || $scope.showDetailsControls || $scope.showDateControls || $scope.showDateRange || $scope.showTypeAndMergedControls) {
            $scope.showSaveAndLoadControls = false;
            $scope.showTeamAndApplicationControls = false;
            $scope.showDetailsControls = false;
            $scope.showDateControls = false;
            $scope.showDateRange = false;
            $scope.showTypeAndMergedControls = false;
        } else {
            $scope.showSaveAndLoadControls = true;
            $scope.showTeamAndApplicationControls = true;
            $scope.showDetailsControls = true;
            $scope.showDateControls = true;
            $scope.showDateRange = true;
            $scope.showTypeAndMergedControls = true;
        }
    };

    $scope.$watch(function() { return $scope.parameters; }, $scope.refresh, true);

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
//        $scope.refresh();
    }

    $scope.$on('application', function($event, application) {
        $scope.treeApplication = application;
        $scope.parameters.applications = [ application ];
    });

    $scope.$on('team', function($event, team) {
        $scope.treeTeam = team;
        $scope.parameters.teams = [ team ];
    });

    $scope.$on('loadVulnerabilitySearchTable', function(event) {
        if (!$scope.teams) {
            threadfixAPIService.getVulnSearchParameters()
                .success(function(data, status, headers, config) {
                    if (data.success) {
                        $scope.teams = data.object.teams;
                        $scope.scanners = data.object.scanners;
                        $scope.genericVulnerabilities = data.object.vulnTypes;
                        $scope.searchApplications = data.object.applications;
                        $scope.savedFilters = data.object.savedFilters;
                    }
                    $scope.resetFilters();
                }).
                error(function(data, status, headers, config) {
                    $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                    $scope.loadingTree = false;
                });
        } else {
            $scope.resetFilters();
        }
    });

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
                } else if (data.message) {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loadingTree = false;
            }).
            error(function(data, status, headers, config) {
                console.log("Got " + status + " back.");
                $scope.errorMessage = "Failed to retrieve vulnerability tree. HTTP status was " + status;
                $scope.loadingTree = false;
            });
    }

    $scope.refresh = function() {
        $scope.loading = true;
        vulnSearchParameterService.updateParameters($scope, $scope.parameters);

//        refreshVulnTable($scope.parameters);
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
        resetDateRange();
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
        resetDateRange();
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

    var resetDateRange = function(){
        // Reset Date Range
        $scope.startDate = null;
        $scope.startDateOpened = false;
        $scope.endDate = null;
        $scope.endDateOpened = false;
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

    $scope.deleteCurrentFilter = function() {
        if ($scope.selectedFilter) {
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
    }

    $scope.loadFilter = function(filter) {

        $scope.selectedFilter = filter;
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

                        $scope.savedFilters.forEach(function(filter) {
                            if (filter.name === $scope.currentFilterNameInput) {
                                $scope.selectedFilter = filter;
                            }
                        });

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

    $scope.applyElementChecked = function(element) {
        element.vulns.forEach(function(vuln) {
            vuln.checked = element.checked;
        });
    }

    $scope.applyVulnerabilityChecked = function(element, vulnerability) {
        if (!vulnerability.checked) {
            element.checked = false;
        } else {
            var checked = true;

            element.vulns.forEach(function(vuln) {
                if (!vuln.checked) {
                    checked = false;
                }
            });

            element.checked = checked;
        }
    }


    $scope.exportCSV = function() {
        console.log('Downloading vulnerabilities list');

        var parameters = angular.copy($scope.parameters);

        vulnSearchParameterService.updateParameters($scope, parameters);

        $http.post(tfEncoder.encode("/reports/search/export/csv"), parameters).
            success(function(data, status, headers, config, response) {
//                var element = angular.element('<a/>');
//                element.attr({
//                    href: 'data:attachment/csv;charset=utf-8,' + encodeURI(data),
//                    target: '_blank',
//                    download: 'search_export.csv'
//                })[0].click();
//

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
                else
                {
                    // Get the blob url creator
                    var urlCreator = window.URL || window.webkitURL || window.mozURL || window.msURL;
                    if(urlCreator)
                    {
                        // Try to use a download link
                        var link = document.createElement("a");
                        if("download" in link)
                        {
                            // Prepare a blob URL
                            var blob = new Blob([data], { type: contentType });
                            var url = urlCreator.createObjectURL(blob);
                            link.setAttribute("href", url);

                            // Set the download attribute (Supported in Chrome 14+ / Firefox 20+)
                            link.setAttribute("download", filename);

                            // Simulate clicking the download link
                            var event = document.createEvent('MouseEvents');
                            event.initMouseEvent('click', true, true, window, 1, 0, 0, 0, 0, false, false, false, false, 0, null);
                            link.dispatchEvent(event);

                            console.log("Download link Success");

                        } else {
                            // Prepare a blob URL
                            // Use application/octet-stream when using window.location to force download
                            var blob = new Blob([data], { type: octetStreamMime });
                            var url = urlCreator.createObjectURL(blob);
                            window.location = url;

                            console.log("window.location Success");
                        }

                    } else {
                        console.log("Not supported");
                    }
                }

            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve vulnerability report. HTTP status was " + status;
                $scope.loadingTree = false;
            });
    }

    $scope.$on('scanUploaded', function() {
        $scope.refresh();
        $scope.refreshHeading();
    });

    $scope.$on('scanDeleted', function() {
        $scope.refresh();
        $scope.refreshHeading();
    });

    $scope.refreshHeading = function() {
        $http.get(tfEncoder.encode("/reports/update/heading/"+ $scope.$parent.appId)).
            success(function(data, status, headers, config, response) {
                $rootScope.$broadcast('scans', data.object.scans);
                $rootScope.$broadcast('numVulns',  data.object.numVulns);
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve heading information. HTTP status was " + status;
                $scope.loadingTree = false;
            });
    }

});

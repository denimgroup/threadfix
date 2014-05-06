var myAppModule = angular.module('threadfix')

myAppModule.controller('VulnTableController', function ($scope, $window, $http, $rootScope, $modal, $log, tfEncoder) {

    var currentUrl = "/organizations/" + $scope.$parent.teamId + "/applications/" + $scope.$parent.appId;

    $scope.initialized = false;

    $scope.page = 1;

    $scope.vulnType = 'Open';

    $scope.sortType = 'Type';
    $scope.sort = 1;

    var getCweFilter = function() {
        if ($scope.cweFilter) {
            var myRe = /CWE ([0-9]+)/g;
            var myArray = myRe.exec($scope.cweFilter)
            if (myArray) {
                return myArray[1];
            }
        }

        return '';
    };

    // TODO refactor this controller into several controllers
    // /organizations/{orgId}/applications/{applicationId}/vulnerabilities/{vulnerabilityId}/addComment

    $scope.showCommentForm = function(vuln) {
        var modalInstance = $modal.open({
            templateUrl: 'vulnCommentForm.html',
            controller: 'GenericModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode(currentUrl + "/vulnerabilities/" + vuln.id + "/addComment");
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

    $scope.setSort = function(newSortType) {

        $scope.sort = newSortType === $scope.sortType ?
            ($scope.sort == 2 ? 1 : 2) : 1;

        $scope.page = 1;
        $scope.sortType = newSortType;
        $scope.refresh(true, false);

    };

    var getTableSortBean = function(vulnIds) {
        var object = {
            page: $scope.page,
            cweFilter: getCweFilter(),
            severityFilter: $scope.severityFilter,
            parameterFilter: $scope.parameterFilter,
            locationFilter: $scope.locationFilter,
            sort: $scope.sort // 1 is ascending, 2 is descending
        }

        var field = ["",
            "Type",
            "Severity",
            "Path",
            "Parameter"].indexOf($scope.sortType);

        object.field = field;

        if (vulnIds) {
            object.vulnerabilityIds = vulnIds;
        }

        // TODO figure out a better way to do this
        if ($scope.vulnType === 'Open') {
            object.open = true;
        } else if ($scope.vulnType === 'Closed') {
            object.closed = true;
        } else if ($scope.vulnType === 'False Positive') {
            object.falsePositive = true;
        }

        return object;
    }

    $scope.heading = '0 Vulnerabilities';

    $scope.goToPage = function(valid) {
        if (valid) {
            $scope.page = $scope.pageInput;
        }
    }

    $scope.goTo = function(vuln) {
        $window.location.href = tfEncoder.encode(currentUrl + "/vulnerabilities/" + vuln.id);
    };

    $scope.dateToString = function(date) {
        var time = new Date(date)
        return (time.getMonth() + "/" + time.getDate() + "/" + time.getFullYear() + " " + time.getHours() + ":" + time.getMinutes());
    }
    var setDate = function(finding) {
        finding.importTime = $scope.dateToString(finding.importTime);
    }

    $scope.expand = function(vuln) {
        vuln.expanded = !vuln.expanded
        vuln.findings.forEach(setDate);
    }

    $scope.toggleAll = function() {
        var check = function(vuln) {
            vuln.checked = !$scope.allSelected;
        }

        $scope.vulns.forEach(check);
    }

    $scope.setCheckedAll = function(checked) {
        if (checked) {
            $scope.allSelected = false;
        } else {

            if ($scope.vulns.filter(function(vuln) {
                return !vuln.checked;
            }).length === 1) { // the checkbox that calls this action isn't checked yet
                $scope.allSelected = true;
            }
        }
    }

    // define refresh

    var calculateShowTypeSelect = function() {
        $scope.showTypeSelect = [$scope.numClosed, $scope.numHidden, $scope.numFalsePositive].filter(function(number) {
            return number > 0;
        }).length > 0;
    }

    var refreshSuccess = function(data) {
        $scope.vulns = data.object.vulnerabilities;
        $scope.vulns.forEach(sortFindings);
        $scope.genericVulnerabilities = data.object.genericVulnerabilities;
        $scope.numVulns = data.object.numVulns;
        $scope.max = Math.ceil(data.object.numVulns/100);
        $scope.numClosed = data.object.numClosed;
        $scope.numOpen = data.object.numOpen;
        $scope.numHidden = data.object.numHidden;
        $scope.numFalsePositive = data.object.numFalsePositive;
        $scope.empty = $scope.numVulns === 0;
        $rootScope.$broadcast('scans', data.object.scans);
        $scope.allSelected = false;

        if ($scope.numVulns === 0 && !$scope.hasFilters()) {
            $scope.vulnType = 'Open';
        }

        if (!$scope.vulns) {
            $scope.vulns = [];
        }

        $scope.filtered = $scope.hasFilters();

        $scope.loading = false;

        calculateShowTypeSelect();
    }

    var sortFindings = function(vuln) {
        vuln.findings.sort(function(a, b) {
            if (a.importTime < b.importTime) return 1;
            if (a.importTime > b.importTime) return -1;
            return 0;
        });
    }

    // Listeners / refresh stuff
    $scope.refresh = function(newValue, oldValue) {
        if (newValue !== oldValue) {
            $scope.loading = true;
            $http.post(tfEncoder.encode(currentUrl + "/table"),
                    getTableSortBean()).
                success(function(data, status, headers, config) {
                    $scope.initialized = true;

                    if (data.success) {
                        refreshSuccess(data);
                    } else {
                        $scope.output = "Failure. Message was : " + data.message;
                    }

                    $scope.loading = false;
                }).
                error(function(data, status, headers, config) {
                    $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                    $scope.loading = false;
                });
        }
    };

    // Define listeners
    $scope.$watch('vulnType', $scope.refresh);

    $scope.$on('rootScopeInitialized', function() {
        return $scope.refresh(true, false);
    });

    $scope.$watch('page', $scope.refresh); // TODO look at caching some of this

    $scope.$watch('numVulns', function() {

        var descriptor = $scope.vulnType;

        if ($scope.hasFilters()) {
            descriptor = 'Filtered ' + descriptor;
        }

        if ($scope.numVulns === 1) {
            $scope.heading = '1 ' + descriptor + ' Vulnerability';
        } else {
            $scope.heading = $scope.numVulns + ' ' + descriptor + ' Vulnerabilities';
        }
    });

    $scope.$on('scanUploaded', function() {
        $scope.empty = false;
        $scope.refresh(true, false);
    });

    $scope.$on('application', function(event, application) {
        $scope.application = application;
    });

    $scope.$on('scanDeleted', function() {
        $scope.refresh(true, false);
        $scope.empty = $scope.numVulns === 0;
    });

    // Define bulk operations

    var bulkOperation = function(urlExtension) {

        $scope.submitting = true;

        var object = getTableSortBean($scope.vulns.filter(function(vuln) {
            return vuln.checked;
        }).map(function(vuln) {
            return vuln.id
        }));
        $scope.loading = true;

        $http.post(tfEncoder.encode(currentUrl + urlExtension), object).
            success(function(data, status, headers, config) {

                if (data.success) {
                    refreshSuccess(data);
                } else {
                    $scope.output = "Failure. Message was : " + data.message;
                }
                $scope.submitting = false;

            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed. HTTP status was " + status;
                $scope.submitting = false;
            });
    }

    $scope.closeVulnerabilities = function() {
        bulkOperation("/table/close");
    }

    $scope.openVulnerabilities = function() {
        bulkOperation("/table/open");
    }

    $scope.markFalsePositives = function() {
        bulkOperation("/falsePositives/mark");
    }

    $scope.unmarkFalsePositives = function() {
        bulkOperation("/falsePositives/unmark");
    }

    $scope.hasFilters = function() {
        return $scope.cweFilter || $scope.severityFilter || $scope.parameterFilter || $scope.locationFilter;
    }

    $scope.clearFilters = function() {
        var shouldRefresh = $scope.hasFilters();

        $scope.cweFilter = '';
        $scope.severityFilter = '';
        $scope.parameterFilter = '';
        $scope.locationFilter = '';

        if (shouldRefresh) {
            $scope.refresh(true, false);
        }
    }

    // Defect submission modal
    // should close over $scope but let's see
    var localRefresh = function() {
        $scope.refresh(true, false);
    }

    $scope.showSubmitDefectModal = function() {

        var filteredVulns = $scope.vulns.filter(function(vuln) {
            return vuln.checked;
        });

        if (filteredVulns.length === 0) {
            alert('You must select at least one vulnerability.');
            return;
        }

        filteredVulns = filteredVulns.filter(function(vuln) {
            return !vuln.defect;
        })

        if (filteredVulns.length === 0) {
            alert('All of the selected vulnerabilities already have defects.');
            return;
        }

        var modalInstance = $modal.open({
            windowClass: 'submit-defect-form',
            templateUrl: 'submitDefectForm.html',
            controller: 'DefectSubmissionModalController',
            resolve: {
                url: function() {
                    var app = $scope.application;
                    return tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id + "/defects");
                },
                configUrl: function() {
                    var app = $scope.application;
                    return tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id + "/defectSubmission");
                },
                object: function () {
                    return {};
                },
                config: function() {
                    return {
                        vulns: filteredVulns,
                        typeName: $scope.application.defectTracker.defectTrackerType.name
                    }
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (s) {
            $scope.successMessage = "Successfully merged the vulnerability.";
            localRefresh();
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.showMergeDefectModal = function() {

        var filteredVulns = $scope.vulns.filter(function(vuln) {
            return vuln.checked;
        });

        if (filteredVulns.length === 0) {
            alert('You must select at least one vulnerability.');
            return;
        }

        filteredVulns = filteredVulns.filter(function(vuln) {
            return !vuln.defect;
        })

        if (filteredVulns.length === 0) {
            alert('All of the selected vulnerabilities already have defects.');
            return;
        }

        var modalInstance = $modal.open({
            windowClass: 'submit-defect-form',
            templateUrl: 'mergeDefectForm.html',
            controller: 'DefectSubmissionModalController',
            resolve: {
                url: function() {
                    var app = $scope.application;
                    return tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id + "/defects/merge");
                },
                configUrl: function() {
                    var app = $scope.application;
                    return tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id + "/defectSubmission");
                },
                object: function () {
                    return {};
                },
                config: function() {
                    return {
                        vulns: filteredVulns
                    }
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (returnValue) {
            $scope.successMessage = "Successfully merged the vulnerability.";
            localRefresh();
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

});
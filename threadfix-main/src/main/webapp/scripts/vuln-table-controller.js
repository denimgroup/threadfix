var myAppModule = angular.module('threadfix')

myAppModule.controller('VulnTableController', function ($scope, $window, $http, $rootScope, $modal, $log) {

    $scope.initialized = false;

    $scope.page = 1;

    $scope.vulnType = 'Open';

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

    var getTableSortBean = function(vulnIds) {
        var object = {
            page: $scope.page,
            cweFilter: getCweFilter(),
            severityFilter: $scope.severityFilter,
            parameterFilter: $scope.parameterFilter,
            locationFilter: $scope.locationFilter
        }

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

    $scope.csrfToken = $scope.$parent.csrfToken;

    $scope.heading = '0 Vulnerabilities';

    $scope.goToPage = function() {
        $scope.page = $scope.pageInput;
    }

    var setDate = function(finding) {
        var time = new Date(finding.importTime)
        finding.importTime = (time.getMonth() + "/" + time.getDate() + "/" + time.getFullYear() + " " + time.getHours() + ":" + time.getMinutes());
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
        $scope.genericVulnerabilities = data.object.genericVulnerabilities;
        $scope.numVulns = data.object.numVulns;
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

    // Listeners / refresh stuff
    $scope.refresh = function(newValue, oldValue) {
        if (newValue !== oldValue) {
            $scope.loading = true;
            $http.post($window.location.pathname + "/table" + $scope.csrfToken,
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

    $scope.$watch('csrfToken', function() {
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
        $scope.refresh();
    });

    $scope.$on('application', function(event, application) {
        $scope.application = application;
    });

    $scope.$on('scanDeleted', function() {
        $scope.refresh();
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

        $http.post($window.location.pathname + urlExtension + $scope.csrfToken, object).
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
                    return "/organizations/" + app.team.id + "/applications/" + app.id + "/defects" + $scope.csrfToken;
                },
                configUrl: function() {
                    var app = $scope.application;
                    return "/organizations/" + app.team.id + "/applications/" + app.id + "/defectSubmission" + $scope.csrfToken;
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
                    return "/organizations/" + app.team.id + "/applications/" + app.id + "/defects/merge" + $scope.csrfToken;
                },
                configUrl: function() {
                    var app = $scope.application;
                    return "/organizations/" + app.team.id + "/applications/" + app.id + "/defectSubmission" + $scope.csrfToken;
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
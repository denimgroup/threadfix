var module = angular.module('threadfix');

//essentially a copy of BulkOperationsController, copy and not factorized to avoid conflicts in the future
module.controller('VulnOperationsController', function($window, $rootScope, $http, $log, $modal, tfEncoder, $scope) {

    var $parent = $scope.$parent;

    //changing way to get application
    var getApplication = function() {
        return $scope.vulnerability.app;
    };

    var getAppUrlBase = function () {
        var app = getApplication();
        return "/organizations/" + app.team.id + "/applications/" + app.id;
    };

    //Changing return value here
    var getFilteredVulns = function() {
        // here inserting the single vuln intead of the filtered list
        var filteredVulns = [$scope.vulnerability];

        return filteredVulns;
    };

    $scope.showSubmitGrcControlModal = function() {

        var filteredVulns = getFilteredVulns();

        if (filteredVulns.length === 0) {
            alert('You must select at least one vulnerability.');
            return;
        }

        filteredVulns = filteredVulns.filter(function(vuln) {
            return !vuln.grcControl;
        });

        if (filteredVulns.length === 0) {
            alert('All of the selected vulnerabilities already have controls.');
            return;
        }

        var modalInstance = $modal.open({
            templateUrl: 'submitGrcControlLoadingModal.html',
            controller: 'GRCControlSubmissionModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode(getAppUrlBase() + "/controls");
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
            $scope.refresh();
            $parent.successMessage = s;
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.showSubmitDefectModal = function() {

        var filteredVulns = getFilteredVulns();

        if (filteredVulns.length === 0) {
            alert('You must select at least one vulnerability.');
            return;
        }

        filteredVulns = filteredVulns.filter(function(vuln) {
            return !vuln.defect;
        });

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
                    return tfEncoder.encode(getAppUrlBase() + "/defects");
                },
                configUrl: function() {
                    return tfEncoder.encode(getAppUrlBase() + "/defectSubmission");
                },
                object: function () {
                    return {};
                },
                config: function() {
                    return {
                        vulns: filteredVulns,
                        typeName: getApplication().defectTracker.defectTrackerType.name
                    }
                },
                defectDefaultsConfig: function() {
                    return {
                        defectTrackerId : getApplication().defectTracker.id,
                        mainDefaultProfile : getApplication().mainDefaultDefectProfile // may be null
                    };
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (s) {
            $scope.refresh();
            $parent.successMessage = "Successfully submitted the defect: " + s;
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.showMergeDefectModal = function() {

        var filteredVulns = getFilteredVulns();

        if (filteredVulns.length === 0) {
            alert('You must select at least one vulnerability.');
            return;
        }

        filteredVulns = filteredVulns.filter(function(vuln) {
            return !vuln.defect;
        });

        if (filteredVulns.length === 0) {
            alert('All of the selected vulnerabilities already have defects.');
            return;
        }

        var modalInstance = $modal.open({
            windowClass: 'submit-defect-form',
            templateUrl: 'addToExistingDefect.html',
            controller: 'AddToExistingDefectController',
            resolve: {
                url: function() {
                    return tfEncoder.encode(getAppUrlBase() + "/defects/merge");
                },
                configUrl: function() {
                    return tfEncoder.encode(getAppUrlBase() + "/defectSubmissionWithIssues");
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

            $scope.refresh();
            $parent.successMessage = returnValue;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.closeVuln = function(){
        var url = tfEncoder.encode(getAppUrlBase() + "/vulnerabilities/" + $scope.vulnerability.id + "/close");
        sendGetRequest(url);
    };

    $scope.openVuln = function(){
        var url = tfEncoder.encode(getAppUrlBase() + "/vulnerabilities/" + $scope.vulnerability.id + "/open");
        sendGetRequest(url);
    };

    $scope.markFalsePositive = function(){
        var url = tfEncoder.encode(getAppUrlBase() + "/vulnerabilities/" + $scope.vulnerability.id + "/markFalsePositive");
        sendGetRequest(url);
    };

    $scope.unmarkFalsePositive = function(){
        var url = tfEncoder.encode(getAppUrlBase() + "/vulnerabilities/" + $scope.vulnerability.id + "/markNotFalsePositive");
        sendGetRequest(url);
    };

    $scope.viewDefect = function(){
        $window.location.href = tfEncoder.encode(getAppUrlBase() + "/vulnerabilities/" + $scope.vulnerability.id + "/defect");

    };

    var sendGetRequest = function(url) {
        $http.get(url).
            success(function(data, status, headers, config) {
                if (data.success) {
                    $parent.successMessage = data.object;
                    $scope.refresh();

                } else {
                    $parent.errorMessage = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $parent.errorMessage = "Failed to retrieve waf list. HTTP status was " + status;
            });
    }

});
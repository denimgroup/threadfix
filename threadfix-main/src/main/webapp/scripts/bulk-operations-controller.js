var module = angular.module('threadfix');

module.controller('BulkOperationsController', function($rootScope, $http, $log, $modal, $window, tfEncoder, urlIdShortener, $scope) {

    var $parent = $scope.$parent;

    var getApplication = function() {
        return ($parent.treeApplication) ? $parent.treeApplication : {id: -1};
    };

    var getTeam = function(){
        return ($parent.treeApplication) ? $parent.treeApplication.team : $parent.treeTeam;
    };

    var getAppUrlBase = function () {
        return "/organizations/" + getTeam().id + "/applications/" + getApplication().id;
    };

    var getFilteredVulns = function() {
        var filteredVulns = [];
        var tempResults;

        $parent.vulnTree.forEach(function(category) {
            category.entries.forEach(function(entry) {
                if (entry.vulns) {
                    tempResults = entry.vulns.filter(function(vuln) {
                        vuln.severityId = entry.intValue;
                        vuln.vulnerabilityName = entry.genericVulnerability.name;
                        return vuln.checked;
                    });
                    filteredVulns = filteredVulns.concat(tempResults);
                }
            });
        });

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
            $rootScope.$broadcast('successMessage', s);
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
                typeAheadUrl: function() {
                    return tfEncoder.encode(getAppUrlBase() + "/typeAheadData")
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
            $rootScope.$broadcast('successMessage', "Successfully submitted the defect: " + s);
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
            $rootScope.$broadcast('successMessage', returnValue);
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    var bulkOperation = function(urlExtension, messageExtension) {

        $scope.submitting = true;

        var object = {};
        object.vulnerabilityIds = getFilteredVulns().map(function(vuln) {
            return vuln.id;
        });

        $scope.loading = true;

        $http.post(tfEncoder.encode(getAppUrlBase() + urlExtension), object).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $parent.successMessage = object.vulnerabilityIds.length + " vulnerabilities successfully " + messageExtension + ".";
                    $parent.refresh();
                    $rootScope.$broadcast('scanUploaded');
                } else {
                    $parent.errorMessage = "Failure. Message was : " + data.message;
                }
                $scope.submitting = false;

            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failure. " + (data && data.message ? "Message was " + data.message : "") + ". HTTP status was " + status;
                $scope.submitting = false;
            });
    };

    $scope.closeVulnerabilities = function() {
        bulkOperation("/table/close", "closed");
    };

    $scope.openVulnerabilities = function() {
        bulkOperation("/table/open", "reopened");
    };

    $scope.markFalsePositives = function() {
        bulkOperation("/falsePositives/mark", "marked false positive");
    };

    $scope.unmarkFalsePositives = function() {
        bulkOperation("/falsePositives/unmark", "unmarked false positive");
    };

    $scope.changeSeverity = function(genericSeverity) {
        bulkOperation("/severity/change/" + genericSeverity.id, "changed severities");
    };

    $scope.addBatchComment = function(tags) {

        var filteredVulns = getFilteredVulns();
        var modalInstance = $modal.open({
            templateUrl: 'vulnCommentForm.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode(getAppUrlBase() + "/addBatchComment");
                },
                object: function () {
                    return {vulnerabilityIds : filteredVulns.map(function(vuln) {
                        return vuln.id;
                    })};
                },
                config: function() {
                    return {tags: tags};
                },
                buttonText: function() {
                    return "Add Comment";
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (comment) {
            filteredVulns.forEach(function(vuln){
               if (!vuln.vulnerabilityComments)
                   vuln.vulnerabilityComments = [];
                vuln.vulnerabilityComments.push(comment);
            });
            $log.info("Successfully added comment.");
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };


    $scope.addBatchTagging = function(tags) {

        var filteredVulns = getFilteredVulns();
        var modalInstance = $modal.open({
            templateUrl: 'vulnTaggingForm.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode(getAppUrlBase() + "/addBatchVulnTagging");
                },
                object: function () {
                    return {vulnerabilityIds : filteredVulns.map(function(vuln) {
                        return vuln.id;
                    })};
                },
                config: function() {
                    return {tags: tags};
                },
                buttonText: function() {
                    return "Batch Tagging";
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (selectedTags) {
            filteredVulns.forEach(function(vuln){
                vuln.tags = selectedTags;
            });
            $log.info("Successfully tagged to vulnerabilities.");
            $scope.successMessage = "Successfully tagged to vulnerabilities.";
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.goToBatchReview = function(){
        var filteredVulns = getFilteredVulns();
        if (filteredVulns.length === 0) {
            alert('You must select at least one vulnerability.');
            return;
        }

        var encodedVulnIdsList = filteredVulns.map(function(vuln){
            return urlIdShortener.encode(vuln.id);
        });
        var encodedVulnIds = encodedVulnIdsList.join("-");
        $window.location.href = tfEncoder.encode(getAppUrlBase() + "/vulnerabilities/" + filteredVulns[0].id + "/batch/" + encodedVulnIds + "/1");
    }

});
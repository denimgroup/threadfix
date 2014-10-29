var myAppModule = angular.module('threadfix')

myAppModule.controller('ApplicationPageModalController', function($scope, $rootScope, $window, $log, $http, $modal, tfEncoder, timeoutService) {

    var currentUrl = "/organizations/" + $scope.$parent.teamId + "/applications/" + $scope.$parent.appId;

    $scope.currentModal = null;

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    // initialize objects for forms
    $scope.$on('rootScopeInitialized', function() {
       $http.get(tfEncoder.encode(currentUrl + "/objects")).
           success(function(data, status, headers, config) {

               if (data.success) {
                   $scope.config = data.object;
                   if (!$scope.config.wafList) {
                       $scope.config.wafList = [];
                   }
                   if (!$scope.config.defectTrackerList) {
                       $scope.config.defectTrackerList = [];
                   }
                   if (!$scope.config.recentFileList) {
                       $scope.config.recentFileList = [];
                   }
                   if (!$scope.config.recentPathList) {
                       $scope.config.recentPathList = [];
                   }
                   if ($scope.config.teams) {
                       $scope.config.teams.sort(nameCompare);
                   }
                   if (!$scope.config.tags)
                       $scope.config.tags = [];

                   if (!$scope.config.applicationTags)
                       $scope.config.applicationTags = [];

                   $scope.config.tags.forEach(function(dbTag){
                       $scope.config.applicationTags.some(function(appTag){
                           if (dbTag.id === appTag.id) {
                               dbTag.selected = true;
                               return true;
                           }
                       })
                   })

                   $scope.config.trackerTypes = $scope.config.defectTrackerTypeList;

                   $rootScope.$broadcast('seeMoreExtension', "/" + $scope.config.application.team.id + "/" + $scope.config.application.id);

                   $rootScope.$broadcast('scheduledScans', $scope.config.scheduledScans);
                   $rootScope.$broadcast('scanAgentTasks', $scope.config.scanAgentTasks);
                   $rootScope.$broadcast('application', $scope.config.application);
                   $rootScope.$broadcast('scans', $scope.config.scans);
                   $rootScope.$broadcast('documents', $scope.config.documents);

                   $rootScope.$broadcast('loadVulnerabilitySearchTable');

                   $scope.config.application.organization = $scope.config.application.team;
                   $scope.$parent.application = $scope.config.application;
               } else {
                   $log.info("HTTP request for form objects failed. Error was " + data.message);
               }
           }).
           error(function(data, status, headers, config) {
                $log.info("HTTP request for form objects failed.");
               // TODO improve error handling and pass something back to the users
               $scope.errorMessage = "Request to server failed. Got " + status + " response code.";
           });
    });

    $scope.updateDefectStatus = function() {
        timeoutService.timeout();
        $http.get(tfEncoder.encode(currentUrl + "/defects/update")).
            success(function(data, status, headers, config) {
                timeoutService.cancel();
                if (data.success) {
                    $scope.successMessage = data.object;
                } else {
                    $log.info("Request to update defect statuses failed. Error was " + data.message);
                }
            }).
            error(function(data, status, headers, config) {
                timeoutService.cancel();
                $log.info("HTTP request for form objects failed.");
                // TODO improve error handling and pass something back to the users
                $scope.errorMessage = "Request to server failed. Got " + status + " response code.";
            });
    };

    // Handle the complex modal interactions on the edit application modal
    $scope.$on('modalSwitch', function(event, name) {
        $scope.currentModal.dismiss('modalChanged');
        if (name === 'addWaf') {
            if (!$scope.config.wafList) {
                $scope.config.wafList = [];
            }
            if ($scope.config.wafList.length === 0) {
                $scope.showCreateWafModal();
            } else {
                $scope.showAddWafModal();
            }
        } else if (name === 'createWaf') {
            $scope.showCreateWafModal();

        } else if (name === 'addDefectTracker') {
            if (!$scope.config.defectTrackerList) {
                $scope.config.defectTrackerList = [];
            }
            if ($scope.config.defectTrackerList.length === 0) {
                $scope.showCreateDefectTrackerModal();
            } else {
                $scope.showAddDefectTrackerModal(null);
            }

        } else if (name === 'createDefectTracker') {
            $scope.showCreateDefectTrackerModal();
        } else if (name === 'goToWaf') {
            $scope.goToWaf();
        }
    });

    $scope.showEditModal = function() {

        var modalInstance = $modal.open({
            templateUrl: 'editApplicationModal.html',
            controller: 'EditApplicationModalController',
            resolve: {
                url: function() {
                    var app = $scope.config.application;
                    return tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id + "/edit");
                },
                tagsUrl: function() {
                    var app = $scope.config.application;
                    return tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id + "/edit/setTagsEndpoint");
                },
                object: function () {
                    var appCopy = angular.copy($scope.config.application);
                    var app = $scope.config.application;
                    app.deleteUrl = tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id + "/delete");

                    // this is a shim for displaying the unencrypted username and a dummy password
                    appCopy.repositoryUserName = app.obscuredUserName;
                    appCopy.repositoryPassword = app.obscuredPassword;
                    return appCopy;
                },
                config: function() {
                    return $scope.config;
                },
                buttonText: function() {
                    return "Save Changes";
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (application) {
            $scope.config.application = application;
            $scope.$parent.application = application;
            $scope.$parent.successMessage = "Successfully edited application " + application.name;
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    // WAF methods
    $scope.showAddWafModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'addWafModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    var app = $scope.config.application;
                    return tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id + "/edit/wafAjax");
                },
                object: function () {
                    var id = 0;
                    if ($scope.config.application.waf) {
                        id = $scope.config.application.waf.id;
                    }
                    return {
                        waf: {
                            id: id
                        }
                    };
                },
                config: function() {
                    return $scope.config;
                },
                buttonText: function() {
                    return "Add WAF";
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (waf) {
            $scope.config.application.waf = waf;
            $scope.successMessage = "Set waf to " + waf.name;
            $scope.showEditModal();
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.showCreateWafModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'createWafModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/wafs/new/ajax/appPage");
                },
                object: function () {
                    return {
                        wafType: {
                            id: 1
                        },
                        applicationId: $scope.config.application.id
                    };
                },
                config: function() {
                    return $scope.config;
                },
                buttonText: function() {
                    return "Create WAF";
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (waf) {
//            $scope.config.wafs.push(waf);
            if (!$scope.config.wafList || $scope.config.wafList.length === 0) {
                $scope.config.wafList = [];
            }
            $scope.config.wafList.push(waf);
            $scope.config.application.waf = waf;
            $scope.successMessage = "Successfully created waf " + waf.name;
            $scope.showEditModal();
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    // Defect Tracker methods
    $scope.showAddDefectTrackerModal = function(newDt) {
        var modalInstance = $modal.open({
            templateUrl: 'addDefectTrackerModal.html',
            controller: 'AddDefectTrackerModalController',
            resolve: {
                url: function() {
                    var app = $scope.config.application;
                    return tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id + "/edit/addDTAjax");
                },
                object: function () {

                    if (newDt) {
                        return {
                            defectTracker: newDt,
                            defectTrackerId:  newDt.id
                        };
                    }

                    if ($scope.config.application.defectTracker) {
                        return {
                            defectTracker: $scope.config.application.defectTracker,
                            defectTrackerId:  $scope.config.application.defectTracker.id
                        };
                    }

                    return {
                        defectTracker: $scope.config.defectTrackerList[0],
                        defectTrackerId: $scope.config.defectTrackerList[0].id
                    };
                },
                config: function() {
                    return $scope.config;
                },
                buttonText: function() {
                    return "Add Defect Tracker";
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (defectTracker) {
            $scope.config.application.defectTracker = defectTracker;
            $scope.successMessage = "Set defect tracker to " + defectTracker.name;
            $scope.showEditModal();
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.showCreateDefectTrackerModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'newTrackerModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/defecttrackers/new");
                },
                object: function () {
                    return {
                        defectTrackerType: $scope.config.trackerTypes[0],
                        applicationId: $scope.config.application.id
                    };
                },
                config: function() {
                    return $scope.config;
                },
                buttonText: function() {
                    return "Create Defect Tracker";
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (dt) {

            if (!$scope.config.defectTrackerList || $scope.config.defectTrackerList.length === 0) {
                $scope.config.defectTrackerList = [];
            }

            $scope.config.defectTrackerList.push(dt);
//            $scope.config.application.defectTracker = dt;
            $scope.successMessage = "Successfully created waf " + dt.name;
//            $scope.showEditModal();
            $scope.showAddDefectTrackerModal(dt);
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    // Handle fileDragged event and upload scan button clicks
    $scope.$on('fileDragged', function(event, $files) {
        $scope.showUploadForm($files);
    });

    $scope.fileModalOn = false;
    $scope.showUploadForm = function(files) {

        if ($scope.fileModalOn) {
            $rootScope.$broadcast('files', files);
        } else {
            var modalInstance = $modal.open({
                templateUrl: 'uploadScanForm.html',
                controller: 'UploadScanController',
                resolve: {
                    url: function() {
                        var app = $scope.config.application;
                        return tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id + "/upload/remote");
                    },
                    files: function() {
                        return files;
                    }
                }
            });
            $scope.fileModalOn = true;

            modalInstance.result.then(function (scan) {
                $log.info("Successfully uploaded scan.");
                $rootScope.$broadcast('scanUploaded');
                $scope.fileModalOn = false;
            }, function () {
                $log.info('Modal dismissed at: ' + new Date());
                $scope.fileModalOn = false;
            });
        }
    };

    $scope.submitFindingForm = function() {
        var modalInstance = $modal.open({
            templateUrl: 'manualFindingForm.html',
            windowClass: 'wide',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode(currentUrl + "/scans/new");
                },
                object: function () {
                    return {
                        application: {
                            id: $scope.config.application.id
                        },
                        group: "dynamic",
                        dataFlowElements: [{}],
                        channelSeverity: $scope.config.manualSeverities[0]
                    };
                },
                config: function() {
                    return $scope.config;
                },
                buttonText: function() {
                    return "Submit Finding";
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (result) {
            $scope.successMessage = result;
            $rootScope.$broadcast('scanUploaded');
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });

    };

    $scope.goToWaf = function() {
        window.location.href = tfEncoder.encode("/wafs/" + $scope.config.application.waf.id);
    };

    $scope.showUsers = function() {
        $modal.open({
            templateUrl: 'permissibleUsersModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return {};
                },
                object: function () {
                    return {};
                },
                config: function() {
                    return {};
                },
                buttonText: function() {
                    return {};
                }
            }
        });
    };

    $scope.viewApplicationDetail = function() {
        $modal.open({
            templateUrl: 'detailApplicationModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return {};
                },
                object: function () {
                    return {};
                },
                config: function() {
                    return {};
                },
                buttonText: function() {
                    return {};
                }
            }
        });
    };
})

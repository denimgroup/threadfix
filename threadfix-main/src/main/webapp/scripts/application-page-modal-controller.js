var myAppModule = angular.module('threadfix')

myAppModule.controller('ApplicationPageModalController', function($scope, $rootScope, $window, $log, $http, $modal) {

    $scope.csrfToken = $scope.$parent.csrfToken;

    $scope.currentModal = null;

    // initialize objects for forms
    $scope.$watch('csrfToken', function() {
       $http.get($window.location.pathname + "/objects" + $scope.csrfToken).
           success(function(data, status, headers, config) {

               if (data.success) {
                   $scope.config = data.object;
                   if (!$scope.config.wafList) {
                       $scope.config.wafList = [];
                   }
                   if (!$scope.config.defectTrackerList) {
                       $scope.config.defectTrackerList = [];
                   }

                   $rootScope.$broadcast('application', $scope.config.application);
                   $rootScope.$broadcast('scans', $scope.config.scans);
                   $rootScope.$broadcast('documents', $scope.config.documents);

                   $scope.config.application.organization = $scope.config.application.team;
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
        $http.get($window.location.pathname + "/defects/update" + $scope.csrfToken).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.successMessage = data.object;
                } else {
                    $log.info("Request to update defect statuses failed. Error was " + data.message);
                }
            }).
            error(function(data, status, headers, config) {
                $log.info("HTTP request for form objects failed.");
                // TODO improve error handling and pass something back to the users
                $scope.errorMessage = "Request to server failed. Got " + status + " response code.";
            });
    }

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
                $scope.showAddDefectTrackerModal();
            }

        } else if (name === 'createDefectTracker') {
            $scope.showCreateDefectTrackerModal();
        }
    });

    $scope.showEditModal = function() {

        var modalInstance = $modal.open({
            templateUrl: 'editApplicationModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    var app = $scope.config.application;
                    return "/organizations/" + app.team.id + "/applications/" + app.id + "/edit" + $scope.csrfToken;
                },
                object: function () {
                    var app = $scope.config.application;
                    app.deleteUrl = "/organizations/" + app.team.id + "/applications/" + app.id + "/delete" + $scope.csrfToken
                    return $scope.config.application;
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
            $scope.successMessage = "Successfully edited application " + application.name;
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
                    return "/organizations/" + app.team.id + "/applications/" + app.id + "/edit/wafAjax" + $scope.csrfToken;
                },
                object: function () {
                    return {
                        waf: {
                            id: $scope.config.application.waf.id
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
    }

    $scope.showCreateWafModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'createWafModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return "/wafs/new/ajax/appPage" + $scope.csrfToken;
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
            $scope.config.wafs.push(waf);
            $scope.config.application.waf = waf;
            $scope.successMessage = "Successfully created waf " + waf.name;
            $scope.showEditModal();
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    // Defect Tracker methods
    $scope.showAddDefectTrackerModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'addDefectTrackerModal.html',
            controller: 'AddDefectTrackerModalController',
            resolve: {
                csrfToken: function() {
                    return $scope.csrfToken;
                },
                url: function() {
                    var app = $scope.config.application;
                    return "/organizations/" + app.team.id + "/applications/" + app.id + "/edit/addDTAjax" + $scope.csrfToken;
                },
                object: function () {

                    var id = null;
                    if ($scope.config.application.defectTracker) {
                        id = $scope.config.application.defectTracker.id;
                    }

                    return {
                        defectTrackerId: id
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
            $scope.successMessage = "Set waf to " + defectTracker.name;
            $scope.showEditModal();
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.showCreateDefectTrackerModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'createDefectTrackerModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return "/configuration/defecttrackers/new" + $scope.csrfToken;
                },
                object: function () {
                    return {
                        defectTrackerType: {
                            id: 1
                        },
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

        modalInstance.result.then(function (waf) {
            $scope.config.wafs.push(waf);
            $scope.config.application.waf = waf;
            $scope.successMessage = "Successfully created waf " + waf.name;
            $scope.showEditModal();
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }



    // Handle fileDragged event and upload scan button clicks
    $scope.$on('fileDragged', function(event, $files) {
        $scope.showUploadForm($files);
    });

    $scope.showUploadForm = function(files) {
        var modalInstance = $modal.open({
            templateUrl: 'uploadScanForm.html',
            controller: 'UploadScanController',
            resolve: {
                url: function() {
                    var app = $scope.config.application;
                    return "/organizations/" + app.team.id + "/applications/" + app.id + "/upload/remote" + $scope.csrfToken;
                },
                files: function() {
                    return files;
                }
            }
        });

        modalInstance.result.then(function (scan) {
            $log.info("Successfully uploaded scan.");
            $rootScope.$broadcast('scanUploaded');
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });

    }

})

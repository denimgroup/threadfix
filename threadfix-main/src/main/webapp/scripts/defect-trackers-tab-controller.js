var module = angular.module('threadfix')

module.controller('DefectTrackersTabController', function($window, $scope, $http, $modal, $rootScope, $log, tfEncoder, threadFixModalService) {

    $scope.trackers = [];

    $scope.isMissingApplication = {};

    $scope.heading = 'Defect Trackers';

    $scope.loading = true;

    $scope.empty = true;

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/defecttrackers/info')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.trackers = data.object.defectTrackers;

                    $scope.scheduledUpdates = data.object.scheduledUpdates;

                    $scope.empty = $scope.trackers.length === 0;

                    $scope.defectTrackerTypes = data.object.defectTrackerTypes;

                    $scope.trackers.sort(nameCompare);

                    $rootScope.$broadcast('scheduledUpdates', $scope.scheduledUpdates);

                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loading = false;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    });

    $scope.openNewModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'newTrackerModal.html',
            controller: 'CreateEditDefectTrackerModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/defecttrackers/new");
                },
                object: function() {
                    return {
                        defectTrackerType: $scope.defectTrackerTypes[0]
                    };
                },
                config: function() {
                    return {
                        trackerTypes: $scope.defectTrackerTypes
                    };
                },
                buttonText: function() {
                    return "Create Defect Tracker";
                }
            }
        });

        modalInstance.result.then(function (newTracker) {

            $scope.trackers.push(newTracker);

            $scope.empty = $scope.trackers.length === 0;

            $scope.trackers.sort(nameCompare);

            $scope.successMessage = "Successfully created defect tracker " + newTracker.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.openEditModal = function(tracker) {
        var modalInstance = $modal.open({
            templateUrl: 'editTrackerModal.html',
            controller: 'CreateEditDefectTrackerModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/defecttrackers/" + tracker.id + "/edit");
                },
                object: function() {
                    var trackerCopy = angular.copy(tracker);
                    return trackerCopy;
                },
                buttonText: function() {
                    return "Save Edits";
                },
                config: function() {
                    return {
                        trackerTypes: $scope.defectTrackerTypes
                    };
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/configuration/defecttrackers/" + tracker.id + "/delete");
                }
            }
        });

        modalInstance.result.then(function (editedTracker) {

            if (editedTracker) {
                threadFixModalService.deleteElement($scope.trackers, tracker);
                threadFixModalService.addElement($scope.trackers, editedTracker);

                $scope.successMessage = "Successfully edited tracker " + editedTracker.name;
                $scope.trackers.sort(nameCompare);
            } else {

                threadFixModalService.deleteElement($scope.trackers, tracker);
                $scope.empty = $scope.trackers.length === 0 || $scope.trackers == undefined;
                $scope.successMessage = "Defect tracker was successfully deleted.";
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.openUpdateDefectDefaultsModal = function(defaultDefectProfile) {
        var modalInstance = $modal.open({
            windowClass: 'update-defect-defaults',
            templateUrl: 'updateDefectDefaultModal.html',
            controller: 'UpdateDefectDefaultsModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/default/" + defaultDefectProfile.id + "/update");
                },
                configUrl: function() {
                    return tfEncoder.encode("/default/" + defaultDefectProfile.id + "/defectSubmissionForm");
                }
            }
        });
        $scope.currentModal = modalInstance;
        modalInstance.result.then(function () {
            $scope.successMessage = "Successfully updated the defaults for the default defect profile: " + defaultDefectProfile.name;
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.deleteDefaultProfile = function(tracker, defaultDefectProfile) {
        if (confirm("Are you sure you want to delete this profile " + defaultDefectProfile.name + "?")) {
            var deleteUrl = tfEncoder.encode("/default/profiles/delete/" + defaultDefectProfile.id);
            $http.post(deleteUrl).
                success(function(data, status, headers, config) {
                    $scope.successMessage = "Successfully deleted tracker default profile " + defaultDefectProfile.name;
                    threadFixModalService.deleteElement(tracker.defaultDefectProfiles, defaultDefectProfile);
                }).
                error(function(data, status, headers, config) {
                    $scope.error = "Failure. HTTP status was " + status;
                })
            threadFixModalService.deleteElement(tracker.defaultDefectProfiles, defaultDefectProfile);
        }
    };

    $scope.openCreateProfileModal = function(tracker) {
        if (!tracker.applications || tracker.applications == 0){
            $scope.isMissingApplication[tracker.id] = true;
            return;
        }
        var modalInstance = $modal.open({
            templateUrl: 'createDefaultProfileModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/default/addProfile");
                },
                object: function() {
                    var referenceApplication = {id : tracker.applications[0].id};
                    var defectTracker = {id : tracker.id}
                    return {
                        referenceApplication : referenceApplication,
                        defectTracker : defectTracker
                    };
                },
                config: function() {
                    return {
                        referenceApplications: tracker.applications
                    };
                },
                buttonText: function() {
                    return "Add new Default Profile";
                }
            }
        });

        modalInstance.result.then(function (newDefaultProfile) {

            tracker.defaultDefectProfiles.push(newDefaultProfile);
            tracker.defaultDefectProfiles.sort(nameCompare);

            $scope.successMessage = "Successfully created new tracker default profile " + newDefaultProfile.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.openUpdateProfileModal = function(tracker,originalDefaultProfile) {
        if (tracker.applications == 0){
            $scope.isMissingApplication[tracker.id] = true;
            return;
        }
        var defaultProfile = angular.copy(originalDefaultProfile);
        var modalInstance = $modal.open({
            templateUrl: 'updateDefaultProfileModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/default/addProfile");
                },
                deleteUrl: function(){
                    return tfEncoder.encode("/default/profiles/delete/" + defaultProfile.id);
                },
                object: function() {
                    defaultProfile.defectTracker = {id: tracker.id};
                    return defaultProfile;
                },
                config: function() {
                    return {
                        referenceApplications: tracker.applications
                    };
                },
                buttonText: function() {
                    return "Update Default Profile";
                }
            }
        });

        modalInstance.result.then(function (editDefaultProfile) {
            if (editDefaultProfile) {
                //tracker.defaultDefectProfiles.push(editDefaultProfile);

                threadFixModalService.deleteElement(tracker.defaultDefectProfiles, originalDefaultProfile);
                threadFixModalService.addElement(tracker.defaultDefectProfiles, editDefaultProfile);

                $scope.successMessage = "Successfully edited tracker " + editDefaultProfile.name;
                tracker.defaultDefectProfiles.sort(nameCompare);

            } else {
                $scope.successMessage = "Successfully deleted tracker default profile " + originalDefaultProfile.name;
                threadFixModalService.deleteElement(tracker.defaultDefectProfiles, originalDefaultProfile);
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.showDefaultProfiles = function(tracker){
        if  ("showDefaultProfiles" in tracker){
            tracker.showDefaultProfiles = !tracker.showDefaultProfiles;
        }
        else {
            tracker.showDefaultProfiles = true;
        }

        if (tracker.defaultDefectProfiles)
            tracker.defaultDefectProfiles.sort(nameCompare);
    }

    $scope.goToApp = function(app) {
        $window.location.href = tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id);
    }
});
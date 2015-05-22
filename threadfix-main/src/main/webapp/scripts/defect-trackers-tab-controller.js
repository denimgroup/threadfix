var module = angular.module('threadfix')

module.controller('DefectTrackersTabController', function($scope, $http, $modal, $rootScope, $log, tfEncoder, threadFixModalService) {

    $scope.trackers = [];

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

});
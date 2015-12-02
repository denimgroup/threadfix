var myAppModule = angular.module('threadfix');

myAppModule.controller('ScheduledRemoteProviderImportTabController', function ($scope, $window, $modal, $http, $log, $rootScope, tfEncoder) {

    $scope.heading = 'Scheduled Imports';

    $scope.openNewScheduledImportModal = function () {
        var modalInstance = $modal.open({
            templateUrl: 'newScheduledImport.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/remoteproviders/scheduledImports/addImport");
                },
                buttonText: function () {
                    return "Add Scheduled Import";
                },
                heading: function () {
                    return "New Scheduled Import";
                },
                object: function () {
                    return {
                        frequency: 'Daily',
                        hour: '6',
                        minute: '0',
                        period: 'AM',
                        day: 'Sunday',
                        scheduleType: 'SELECT'
                    };
                },
                config: function () {
                    return {
                        heading: 'Remote Provider Import'
                    }
                }
            }
        });

        modalInstance.result.then(function (scheduledImports) {
            $scope.scheduledImports = scheduledImports;
            addExtraZero($scope.scheduledImports);
            setHeader();
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());

        });
    };

    $scope.deleteScheduledImport = function (sImport) {

        if (confirm('Are you sure you want to delete this scheduled import?')) {
            sImport.deleting = true;
            $http.post(tfEncoder.encode("/configuration/remoteproviders/scheduledImports/import/" + sImport.id + "/delete")).
                success(function(data, status, headers, config) {

                    if (data.success) {
                        var index = $scope.scheduledImports.indexOf(sImport);

                        if (index > -1) {
                            $scope.scheduledImports.splice(index, 1);
                        }

                        setHeader();
                        $scope.successMessage = data.object;

                    } else {
                        sImport.deleting = false;
                        $scope.errorMessage = data.object;
                    }
                }).
                error(function(data, status, headers, config) {
                    $log.info("HTTP request for form objects failed.");
                    // TODO improve error handling and pass something back to the users
                    document.deleting = false;
                    $scope.errorMessage = "Request to server failed. Got " + status + " response code.";
                });
        }
    };

    $scope.$on('scheduledImports', function (event, scheduledImports) {
        $scope.scheduledImports = scheduledImports;
        addExtraZero($scope.scheduledImports);
        setHeader();
    });

    var addExtraZero = function (listOfImports) {
        listOfImports.forEach(function(sImport) {
            if (sImport.minute === '0' || sImport.minute === 0) {
                sImport.extraMinute = '0';
            }

            sImport.actualHour = (sImport.hour === '0' || sImport.hour === 0) ? '12' : sImport.hour;

            sImport.timeString = (sImport.day || '') + ' ' + sImport.actualHour + ':' + (sImport.extraMinute || '') + sImport.minute + ' ' + sImport.period;
            sImport.timeStringId = sImport.timeString.replace(/ /g, '_').replace(/:/g, '_');
        });
    };

    var setHeader = function () {
        if (!$scope.scheduledImports || !$scope.scheduledImports.length > 0) {
            $scope.scheduledImports = undefined;
            $scope.heading = "0 Scheduled Imports";
        } else {
            if ($scope.scheduledImports.length === 1) {
                $scope.heading = '1 Scheduled Import';
            } else {
                $scope.heading = $scope.scheduledImports.length + ' Scheduled Imports';
            }
        }
    };

});
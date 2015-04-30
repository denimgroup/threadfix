var myAppModule = angular.module('threadfix');

myAppModule.controller('SystemSettingsController', function ($scope, $window, $modal, $http, $log, $rootScope, tfEncoder) {

    var prevFileUploadLocation;

    $scope.$on('rootScopeInitialized', function() {
        var url = tfEncoder.encode('/configuration/settings/objects');
        $http.get(url).
            success(function(data) {

                if (data.success) {
                    $scope.config = data.object.defaultConfiguration;
                    $scope.roleList = data.object.roleList;
                    $scope.applicationCount = data.object.applicationCount;
                    $scope.licenseCount = data.object.licenseCount;
                    $scope.licenseExpirationDate = data.object.licenseExpirationDate;
                    $scope.dashboardReports = data.object.dashboardReports;
                    $scope.applicationReports = data.object.applicationReports;
                    $scope.teamReports = data.object.teamReports;
                    $scope.successMessage = data.object.successMessage;

                    prevFileUploadLocation = $scope.config.fileUploadLocation;

                    $scope.roleList.unshift({id: 0, displayName: "Read Access"});

                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve LDAP settings. HTTP status was " + status;
            });
    });

    $scope.submit = function (valid) {
        var url = tfEncoder.encode('/configuration/settings/');

        if (valid) {
            $scope.loading = true;

            $http.post(url, $scope.config).
                success(function(data) {
                    $scope.loading = false;

                    if (data.success) {
                        $scope.LDAPSuccessMessage = data.object;
                    } else {
                        $scope.error = "Failure: " + data.message;
                    }
                }).
                error(function(data, status) {
                    $scope.loading = false;
                    $scope.error = "Failure. HTTP status was " + status;
                });
        }
    };


    $scope.shouldDeleteUploadedFiles = function(e, fileUploadLocation) {

        if (prevFileUploadLocation !== '' && fileUploadLocation === '') {
            $scope.deleteUploadedFiles = !!confirm("You've cleared the File Upload Location field. " +
            "Would you like to delete the files residing in that directory?");
        }
    };

    $scope.shouldDisable = function() {
        var returnValue = true;

        if ($scope.config) {
            returnValue = !($scope.config.activeDirectoryBase &&
            $scope.config.activeDirectoryUsername &&
            $scope.config.activeDirectoryCredentials &&
            $scope.config.activeDirectoryURL);
        }

        return returnValue;
    };

    $scope.ok = function (valid) {
        var url = tfEncoder.encode('/configuration/settings/checkLDAP');

        if (valid) {
            $scope.loading = true;

            $http.post(url, $scope.config).
                success(function(data) {
                    $scope.loading = false;

                    if (data.success) {
                        $scope.LDAPSuccessMessage = data.object;
                    } else {
                        $scope.error = "Failure: " + data.message;
                    }
                }).
                error(function(data, status) {
                    $scope.loading = false;
                    $scope.error = "Failure. HTTP status was " + status;
                });
        }
    };

});
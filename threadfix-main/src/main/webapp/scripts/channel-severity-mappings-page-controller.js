var myAppModule = angular.module('threadfix');

myAppModule.controller('ChannelSeverityMappingsPageController', function ($scope, tfEncoder, $http) {

    $scope.$on('rootScopeInitialized', function() {

        $http.get(tfEncoder.encode("/mappings/channelSeverity/map")).
            success(function(data) {

                if (data.success) {
                    $scope.channelTypesData = data.object.channelTypesData;
                    $scope.genericSeverities = data.object.genericSeverities;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });

    });

    $scope.toggle = function(channelType) {

        if (typeof channelType.expanded === "undefined") {
            channelType.expanded = false;
        }

        channelType.expanded = !channelType.expanded;

    };

    $scope.expand = function() {
        $scope.channelTypesData.forEach(function(channelType) {
            channelType.expanded = true;
        });
    };

    $scope.contract = function() {
        $scope.channelTypesData.forEach(function(channelType) {
            channelType.expanded = false;
        });
    };

    $scope.update = function() {
        var updatedChannelSeverities = [];
        $scope.channelTypesData.forEach(function(channelType) {
            channelType.channelSeverities.forEach(function(channelSeverity) {
                if (channelSeverity.changed)
                    updatedChannelSeverities.push(channelSeverity);
            });
        });

        var objectRequest = {"updatedChannelSeverities": JSON.stringify(updatedChannelSeverities),
        "str": "testString"};
        $http.post(tfEncoder.encode("/mappings/channelSeverity/update"), objectRequest).
            success(function(data) {

                if (data.success) {
                    $scope.successMessage = data.object;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });

    };

    $scope.change = function(channelSeverity) {
        channelSeverity.changed = true;
        $scope.severityMapChanged = true;
    }

});
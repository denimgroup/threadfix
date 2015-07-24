var myAppModule = angular.module('threadfix')

myAppModule.controller('TagDetailPageController', function ($scope, $window, $http, $rootScope, tfEncoder) {

    $scope.tagId = $window.location.pathname.match(/([0-9]+)/)[0];
    $scope.currentUrl = "/configuration/tags/" + $scope.tagId;
    $scope.numberToShow = 50;
    $scope.vulnPage = 1;

    $scope.$on('rootScopeInitialized', function() {
        $scope.loading = true;
        $http.get(tfEncoder.encode($scope.currentUrl + '/objects')).
            success(function(data, status, headers, config) {
                $scope.loading = false;
                if (data.success) {
                    $scope.appList = data.object.appList;
                    $scope.vulnListOfVulnTags = data.object.vulnList;
                    $scope.allVulnListOfVulnTags = data.object.vulnList;

                    $scope.allVulnListOfVulnTags.sort(function(vuln1, vuln2){
                        return vuln1.severityId - vuln2.severityId;
                    });

                    $scope.numVulns = $scope.allVulnListOfVulnTags.length;
                    $scope.numberOfPages = Math.ceil($scope.numVulns/$scope.numberToShow);
                    $scope.init($scope.vulnPage);
                    $scope.commentList = data.object.commentList;
                    $scope.type = data.object.type;
                    getVulnList();
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.loading = false;
                $scope.errorMessage = "Failed to retrieve waf list. HTTP status was " + status;
            });
    });

    $scope.init = function(vulnPage){
        $scope.vulnPage = vulnPage;
        $scope.vulnListOfVulnTags = $scope.allVulnListOfVulnTags.slice(($scope.vulnPage-1) * $scope.numberToShow, $scope.vulnPage * $scope.numberToShow);
    }

    $scope.goToPage = function(valid, vulnPageInput) {
        if (valid) {
            $scope.vulnPage = vulnPageInput;
            $scope.init($scope.vulnPage);
        }
    };

    var getVulnList = function(){
        var vulnMap = {};
        $scope.commentList.forEach(function(comment) {
            if (comment.commentInfo.vulnerabilityId) {
                if (!vulnMap[comment.commentInfo.vulnerabilityId]) {
                    vulnMap[comment.commentInfo.vulnerabilityId] = {
                        id : comment.commentInfo.vulnerabilityId,
                        genericVulnerability: {
                            name: comment.commentInfo.vulnerabilityName,
                            displayId: comment.commentInfo.vulnerabilityDisplayId
                        },
                        app : {
                            id: comment.commentInfo.applicationId,
                            name: comment.commentInfo.applicationName
                        },
                        team : {
                            id: comment.commentInfo.teamId,
                            name: comment.commentInfo.teamName
                        },
                        vulnerabilityComments : [{
                            id: comment.commentInfo.commentId,
                            comment: comment.commentInfo.comment,
                            tags: comment.commentInfo.tags,
                            username: comment.commentInfo.username,
                            time: comment.commentInfo.time
                        }],
                        genericSeverity : comment.commentInfo.genericSeverity
                    }
                } else {
                    vulnMap[comment.commentInfo.vulnerabilityId].vulnerabilityComments.push({
                        id: comment.commentInfo.commentId,
                        comment: comment.commentInfo.comment,
                        tags: comment.commentInfo.tags,
                        username: comment.commentInfo.username,
                        time: comment.commentInfo.time
                    })
                }
            }
        })

        $scope.allVulnList = [];
        var keys = Object.keys(vulnMap);
        keys.forEach(function(key){
            $scope.allVulnList.push(vulnMap[key]);
        });

        $scope.allVulnList.sort(function(vuln1, vuln2){
            return vuln2.genericSeverity.intValue - vuln1.genericSeverity.intValue;
        });

        $scope.$broadcast("complianceVulnList", $scope.allVulnList);
    }

    $scope.goToApp = function(app) {
        $window.location.href = tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id);
    };

    $scope.goToTeam = function(app) {
        $window.location.href = tfEncoder.encode("/organizations/" + app.team.id);
    };

    $scope.goToAppFromVuln = function (vuln) {
        $window.location.href = tfEncoder.encode("/organizations/" + vuln.team.id + "/applications/" + vuln.app.id);
    }

    $scope.goToTeamFromVuln = function (vuln) {
        $window.location.href = tfEncoder.encode("/organizations/" + vuln.team.id);
    }

    $scope.goToTag = function (tag) {
        window.location.href = tfEncoder.encode("/configuration/tags/" + tag.id + "/view");
    }

    $scope.goToVuln = function (vuln) {
        $window.location.href = tfEncoder.encode("/organizations/" + vuln.team.id + "/applications/" + vuln.app.id + "/vulnerabilities/" + vuln.id);
    };

    $scope.expand = function (vulnList) {
        vulnList.forEach(function (vuln) {
            vuln.expanded = true;
        });
    };

    $scope.contract = function (vulnList) {
        vulnList.forEach(function (vuln) {
            vuln.expanded = false;
        });
    };

    $scope.toggle = function (vuln) {
        if (typeof vuln.expanded === "undefined") {
            vuln.expanded = false;
        }
        vuln.expanded = !vuln.expanded;
    };

});

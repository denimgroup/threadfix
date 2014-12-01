var module = angular.module('threadfix');

module.controller('VulnSearchTreeController', function($scope, $rootScope, $window, $http, tfEncoder, $modal, $log, vulnSearchParameterService, vulnTreeTransformer) {

    $scope.loadingTree = true;
    $scope.canUpdateVulnComment = false;

    $scope.toggleVulnCategory = function(treeElement, expanded) {
        treeElement.expanded = expanded;
        $scope.checkIfVulnTreeExpanded();
    };

    $scope.checkIfVulnTreeExpanded = function() {
        var expanded = false;

        $scope.vulnTree.forEach(function(treeElement) {
            if(treeElement.expanded){
                expanded = true;
            }
        });

        $scope.vulnTree.expanded = expanded;

        return expanded;
    };

    $scope.toggleVulnTree = function() {
        var expanded = false;

        if ($scope.vulnTree) {
            expanded = $scope.checkIfVulnTreeExpanded();

            $scope.vulnTree.map(function(treeElement){
                treeElement.expanded = !expanded;

                if(treeElement.entries){
                    treeElement.entries.map(function(entry){

                        if(entry.expanded && expanded){
                            entry.expanded = !expanded;
                        }
                    });
                }
            });
        }

        $scope.vulnTree.expanded = !expanded;
    };

    $scope.expandAndRetrieveTable = function(element) {
        $scope.updateElementTable(element, 10, 1);
    };

    // collapse duplicates: [arachni, arachni, appscan] => [arachni (2), appscan]
    var updateChannelNames = function(vulnerability) {
        if (vulnerability.channelNames.length > 1 ) {
            var holder = {};
            vulnerability.channelNames.forEach(function(name) {
                if (holder[name]) {
                    holder[name] = holder[name] + 1;
                } else {
                    holder[name] = 1;
                }
            });

            vulnerability.channelNames = [];
            for (var key in holder) {
                if (holder.hasOwnProperty(key)){
                    if (holder[key] === 1) {
                        vulnerability.channelNames.push(key)
                    } else {
                        vulnerability.channelNames.push(key + " (" + holder[key] + ")")
                    }
                }
            }
        }
    };

    $scope.updateElementTable = function(element, numToShow, page) {
        console.log('Updating element table');

        var parameters = angular.copy($scope.$parent.parameters);

        vulnSearchParameterService.updateParameters($scope.$parent, parameters);
        parameters.genericSeverities = [];
        parameters.genericSeverities.push({ intValue: element.intValue });
        parameters.genericVulnerabilities = [ element.genericVulnerability ];
        parameters.page = page;
        parameters.numberVulnerabilities = numToShow;

        $scope.loadingTree = true;

        $http.post(tfEncoder.encode("/reports/search"), parameters).
            success(function(data, status, headers, config) {
                element.expanded = true;

                if (data.success) {
                    element.vulns = data.object.vulns;
                    element.vulns.forEach(updateChannelNames);
                    element.vulns.forEach(function(vuln){
                        vulnSearchParameterService.updateVulnCommentTags($scope.tags, vuln);
                    });
                    element.totalVulns = data.object.vulnCount;
                    element.max = Math.ceil(data.object.vulnCount/100);
                    element.numberToShow = numToShow;
                    element.page = page;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loadingTree = false;
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                $scope.loadingTree = false;
            });
    };

    $scope.$on('refreshVulnSearchTree', function(event, parameters) {
        $scope.loadingTree = true;
        $http.post(tfEncoder.encode("/reports/tree"), parameters).
            success(function(data, status, headers, config) {
                if (data.success) {
                    $scope.vulnTree = vulnTreeTransformer.transform(data.object);
                    $scope.badgeWidth = 0;
                    if ($scope.vulnTree) {
                        $scope.vulnTree.forEach(function(treeElement) {
                            var size = 7;
                            var test = treeElement.total;
                            while (test >= 10) {
                                size = size + 7;
                                test = test / 10;
                            }

                            //expand each severity level of vulns on page load
                            treeElement.expanded = true;

                            if (size > $scope.badgeWidth) {
                                $scope.badgeWidth = size;
                            }
                        });
                    }

                    $scope.checkIfVulnTreeExpanded();

                    $scope.badgeWidth = { "text-align": "right", width: $scope.badgeWidth + 'px' };
                } else if (data.message) {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loadingTree = false;
            }).
            error(function(data, status, headers, config) {
                console.log("Got " + status + " back.");
                $scope.errorMessage = "Failed to retrieve vulnerability tree. HTTP status was " + status;
                $scope.loadingTree = false;
            });
    });

    $scope.goTo = function(vuln) {
        $window.location.href = tfEncoder.encode($scope.getUrlBase(vuln));
    };

    $scope.getUrlBase = function(vuln) {
        return "/organizations/" + vuln.team.id + "/applications/" + vuln.app.id + "/vulnerabilities/" + vuln.id;
    };

    $scope.showCommentForm = function(vuln, tags) {
        var modalInstance = $modal.open({
            templateUrl: 'vulnCommentForm.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode($scope.getUrlBase(vuln) + "/addComment");
                },
                object: function () {
                    return {};
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

        modalInstance.result.then(function (comments) {
            vuln.vulnerabilityComments = comments;
            $log.info("Successfully added comment.");
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.getDocumentUrl = function(vulnerability, document) {
        return tfEncoder.encode($scope.getUrlBase(vulnerability) + "/documents/" + document.id + "/view");
    };

    $scope.applyElementChecked = function(element) {
        element.vulns.forEach(function(vuln) {
            vuln.checked = element.checked;
        });
    };

    $scope.applyVulnerabilityChecked = function(element, vulnerability) {
        if (!vulnerability.checked) {
            element.checked = false;
        } else {
            var checked = true;

            element.vulns.forEach(function(vuln) {
                if (!vuln.checked) {
                    checked = false;
                }
            });

            element.checked = checked;
        }
    };

    $scope.goToTag = function (tag) {
        window.location.href = tfEncoder.encode("/configuration/tags/" + tag.id + "/view");
    };

});

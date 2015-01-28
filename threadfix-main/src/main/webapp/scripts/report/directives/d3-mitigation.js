var d3ThreadfixModule = angular.module('threadfix');

d3ThreadfixModule.directive('d3Mitigation', ['d3',
    function(d3) {
        return {
            restrict: 'EA',
            scope: {
                data: '=',
                width: '@',
                height: '@'
            }
            ,
            link: function (scope, ele) {
                var width = scope.width,
                    height = scope.height;

                // creating the main svg
                var svg = d3.select(ele[0])
                    .append("svg")
                    .attr("width", width)
                    .attr("height", height)
                    .attr("class", "svg");

                scope.$watch('data', function() {
                    scope.render(scope.data);
                }, true);

                scope.render = function (reportData) {
                    var _data = angular.copy(reportData);

                    if (!_data) return;

                    svg.selectAll('*').remove();
                    var margin = {"left": 30, "bottom": 40, "right": 5};

                    // x scale
                    var xScale = d3.scale.linear()
                        .domain([0, _data.totalNumVuln + 1])
                        .range([0, width - margin.left - margin.right]);

                    var xAxis = d3.svg.axis()
                        .scale(xScale)
                        .ticks(_data.totalNumVuln / 2)
                        .orient("bottom");

                    // y scale
                    var yScale = d3.scale.linear()
                        .domain([0, _data.totalNumVuln + 1])
                        .range([height - margin.bottom, 0]);

                    var yAxis = d3.svg.axis()
                        .scale(yScale)
                        .ticks(_data.totalNumVuln)
                        .orient("left");

                    svg.append("g")
                        .attr("class", "axis")
                        .attr("transform", "translate(20," + (height - 15) + ")")
                        .style({'stroke': 'white', 'fill': 'none', 'stroke-width': '2px'})
                        .call(xAxis);

                    // x-label
                    svg.append("text")
                        .attr("x", 200)
                        .attr("y", 390)
                        .attr("class", "axis wcm-label")
                        .text("Risk")
                        .attr("font-size", "12px")
                        .attr("font-weight", "bold")
                        .attr("fill", "black");

                    svg.append("g")
                        .attr("class", "axis")
                        .attr("transform", "translate(15, 5)")
                        .style({'stroke': 'white', 'fill': 'none', 'stroke-width': '2px'})
                        .call(yAxis);

                    // y-label
                    svg.append("text")
                        .attr("x", 10)
                        .attr("y", 200)
                        .attr("class", "axis wcm-label")
                        .text("Triage")
                        .attr("font-size", "12px")
                        .attr("fill", "black")
                        .attr("font-weight", "bold")
                        .attr("transform", "rotate(270 10,200)");

                    var quadrant_group = svg.append("g")
                        .attr("transform", "translate(" + margin.left + ",0)");

                    var quadrant_border = quadrant_group.append("rect")
                        .attr("x", 0)
                        .attr("y", 0)
                        .attr("width", width - margin.left - margin.right)
                        .attr("height", height - margin.bottom)
                        .attr("rx", 20)
                        .attr("ry", 20)
                        .attr("class", "quadrant_border")
                        .attr("fill", "white")
                        .style({'stroke': '#D0D0D0', 'stroke-width': 1});

                    // creating quadrant descriptions
                    quadrant_group.append("text")
                        .attr("x", xScale(25))
                        .attr("y", yScale(25))
                        .attr("text-anchor", "middle")
                        .text("")
                        .attr("class", "quad-label");

                    quadrant_group.append("text")
                        .attr("x", xScale(25))
                        .attr("y", yScale(75))
                        .attr("text-anchor", "middle")
                        .text("")
                        .attr("class", "quad-label");

                    quadrant_group.append("text")
                        .attr("x", xScale(75))
                        .attr("y", yScale(25))
                        .attr("text-anchor", "middle")
                        .text("")
                        .attr("class", "quad-label");

                    quadrant_group.append("text")
                        .attr("x", xScale(75))
                        .attr("y", yScale(75))
                        .attr("text-anchor", "middle")
                        .text("")
                        .attr("class", "quad-label");

                    // creating the dividers
                    quadrant_group.append("line")
                        .attr("x1", 0)
                        .attr("y1", yScale(_data.totalNumVuln / 2))
                        .attr("x2", xScale(_data.totalNumVuln + 1))
                        .attr("y2", yScale(_data.totalNumVuln / 2))
                        .attr("class", "divider")
                        .style({'stroke': '#D0D0D0', 'stroke-width': 1});

                    quadrant_group.append("line")
                        .attr("x1", xScale(_data.totalNumVuln / 2))
                        .attr("y1", 0)
                        .attr("x2", xScale(_data.totalNumVuln / 2))
                        .attr("y2", yScale(0))
                        .attr("class", "divider")
                        .style({'stroke': '#D0D0D0', 'stroke-width': 1});

                    // xline
                    var gradient = svg.append("defs")
                        .append("linearGradient")
                        .attr("id", "gradient")
                        .attr("x1", "0%")
                        .attr("y1", "10%")
                        .attr("x2", "95%")
                        .attr("y2", "10%")
                        .attr("spreadMethod", "pad");

                    gradient.append("stop")
                        .attr("offset", "0%")
                        .attr("stop-color", "#ff0000")
                        .attr("stop-opacity", 10);

                    gradient.append("stop")
                        .attr("offset", "75%")
                        .attr("stop-color", "#FFCC00")
                        .attr("stop-opacity", 100);

                    gradient.append("stop")
                        .attr("offset", "100%")
                        .attr("stop-color", "#00ff00")
                        .attr("stop-opacity", 1);

                    svg.append("rect")
                        .attr("width", 368)
                        .attr("height", 10)
                        .attr("x", 30)
                        .attr("y", 365)
                        .attr("rx", 10)
                        .attr("ry", 10)
                        .style("fill", "url(#gradient)");

                    // yline
                    var gradient = svg.append("defs")
                        .append("linearGradient")
                        .attr("id", "gradient1")
                        .attr("x1", "90%")
                        .attr("y1", "0%")
                        .attr("x2", "90%")
                        .attr("y2", "85%")
                        .attr("spreadMethod", "pad");

                    gradient.append("stop")
                        .attr("offset", "0%")
                        .attr("stop-color", "#00ff00")
                        .attr("stop-opacity", 1);

                    gradient.append("stop")
                        .attr("offset", "50%")
                        .attr("stop-color", "#FFCC00")
                        .attr("stop-opacity", 100);

                    gradient.append("stop")
                        .attr("offset", "100%")
                        .attr("stop-color", "#ff0000")
                        .attr("stop-opacity", 10);

                    svg.append("rect")
                        .attr("width", 10)
                        .attr("height", 360)
                        .attr("x", 15)
                        .attr("y", 0)
                        .attr("rx", 10)
                        .attr("ry", 10)
                        .style("fill", "url(#gradient1)");

                    quadrant_group.selectAll("circle")
                        .data(_data.results)
                        .enter()
                        .append("circle")
                        .attr("cx", function (d) {

                            var ind = -1, criticalMit = 0, highMit = 0, medMit = 0,
                                lowMit = 0, infoMit = 0, auditMit = 0;

                            if (_data.scanners.length > 0) {
                                angular.forEach(_data.scanners, function (value) {
                                    if (value.name == d.scannerNames) {
                                        ind = _data.scanners.indexOf(value);
                                    }
                                });

                                if (_data.scanners[ind].criticalVulns == true) {
                                    criticalMit += d.criticalO;
                                }
                                if (_data.scanners[ind].highVulns == true) {
                                    highMit += d.highO;
                                }
                                if (_data.scanners[ind].mediumVulns == true) {
                                    medMit += d.medO;
                                }
                                if (_data.scanners[ind].lowVulns == true) {
                                    lowMit += d.lowO;
                                }
                                if (_data.scanners[ind].infoVulns == true) {
                                    infoMit += d.infoO;
                                }
                                if (_data.scanners[ind].auditable == true) {
                                    auditMit += d.auditableO;
                                }
                            }
                            if ((criticalMit + highMit + medMit + lowMit + infoMit + auditMit) > 0) {
                                if (d.closed == 0) {
                                    return xScale(2);
                                } else if (d.closed < d.total && ((criticalMit + highMit + medMit + lowMit + infoMit + auditMit) + d.closed) == d.total) {
                                    return xScale((d.closed * (_data.totalNumVuln / d.total)) - ((criticalMit + highMit + medMit + lowMit + infoMit + auditMit) * (_data.totalNumVuln / 2)));
                                } else {
                                    return xScale(d.closed * ((_data.totalNumVuln - (criticalMit + highMit + medMit + lowMit + infoMit + auditMit)) / d.total));
                                }
                            }
                            else if ((criticalMit + highMit + medMit + lowMit + infoMit + auditMit) == 0) {
                                if (d.closed == d.total)
                                    return xScale(_data.totalNumVuln - 1);
                                else
                                    return xScale((_data.totalNumVuln / 2) + 1 + (d.closed / 2));
                            }
                            else {
                                return xScale(d.closed * (_data.totalNumVuln / d.total));
                            }
                        })
                        .attr("cy", function (d) {
                            var ind = -1, criticalMit = 0, highMit = 0, medMit = 0,
                                lowMit = 0, infoMit = 0, auditMit = 0;

                            if (_data.scanners.length > 0) {
                                angular.forEach(_data.scanners, function (value) {
                                    if (value.name == d.scannerNames)
                                        ind = _data.scanners.indexOf(value);
                                });
                                if (_data.scanners[ind].criticalVulns == true) {
                                    criticalMit += d.criticalO;
                                }
                                if (_data.scanners[ind].highVulns == true) {
                                    highMit += d.highO;
                                }
                                if (_data.scanners[ind].mediumVulns == true)
                                    medMit += d.medO;
                                if (_data.scanners[ind].lowVulns == true) {
                                    lowMit += d.lowO;
                                }
                                if (_data.scanners[ind].infoVulns == true) {
                                    infoMit += d.infoO;
                                }
                                if (_data.scanners[ind].auditable == true) {
                                    auditMit += d.auditableO;
                                }
                            }

                            if ((criticalMit + highMit + medMit + lowMit + infoMit + auditMit) > 0) {
                                if (d.closed == 0) {
                                    return yScale(2);
                                } else if (d.closed < d.total) {
                                    return yScale(d.closed * ((_data.totalNumVuln - (criticalMit + highMit + medMit + lowMit + infoMit + auditMit)) / d.total));
                                }
                            } else if ((criticalMit + highMit + medMit + lowMit + infoMit + auditMit) == 0) {
                                if (d.closed == d.total) {
                                    return yScale(_data.totalNumVuln - 1);
                                }
                                else {
                                    return yScale((_data.totalNumVuln / 2) + 1 + (d.closed / 2));
                                }
                            } else {
                                return yScale(d.closed * (_data.totalNumVuln / d.total));
                            }
                        })
                        .attr("r", function(d) {
                            return 4;
                        })
                        .attr("title", function(d) {
                            return "Name: " + d.scannerNames + "\nTotal: " + d.total +
                                "\nClosed: " + d.closed + "\nCritical: " + d.criticalO + "\nHigh: " + d.highO + "\nMedium: " +
                                d.medO + "\nLow: " + d.lowO + "\nInfo: " + d.infoO
                        })
                        .style("cursor", "pointer")
                        .on("click", function(d) {
                            return _data.viewScan(d.scanId)
                        })
                        .style("fill", function(d) {
                            if (d.criticalO > 0) {
                                return "#F7280C";
                            }
                            else if (d.highO > 0) {
                                return "#F27421";
                            }
                            else if (d.medO > 0) {
                                return "#EFD20A";
                            }
                            else if (d.lowO > 0) {
                                return "#458A37";
                            }
                            else if (d.infoO) {
                                return "#014B6E";
                            }
                            else
                                return "lightgreen";
                        });

                    quadrant_group.selectAll(ele[0].getFirstElementChild)
                        .data([1])
                        .enter()
                        .append("image")
                        .attr("xlink:href", "../../../images/eye.ico")
                        .attr("width", 20)
                        .attr("height", 20)
                        .attr("x", 335)
                        .attr("y", 335)
                        .style("opacity", 0.5)
                        .style("cursor", "pointer")
                        .on("click", function () {
                            return _data.showEditModal();
                        });
                };

            }
        }
    }
]);
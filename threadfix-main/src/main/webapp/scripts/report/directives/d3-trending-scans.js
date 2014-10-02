var d3ThreadfixModule = angular.module('threadfix');

//// Trending scans report
//d3ThreadfixModule.directive('d3Trending_backup', ['d3', 'reportExporter',
//    function(d3, reportExporter) {
//        return {
//            restrict: 'EA',
//            scope: {
//                data: '=',
//                label: '='
//            },
//            link: function(scope, ele, attrs) {
//                var svgWidth = 670, svgHeight = 612,
//                    margin = {top: 70, right: 100, bottom: 200, left: 60},
//                    width = svgWidth - margin.left - margin.right,
//                    height = svgHeight - margin.top - margin.bottom;
//
//                var x = d3.time.scale()
//                    .nice(d3.time.week)
//                    .range([0, width]);
//
//                var y = d3.scale.linear()
//                    .range([height, 0]);
//
//                var monthList = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
//
//                var xAxis = d3.svg.axis()
//                    .scale(x)
//                    .tickSize(3)
//                    .tickFormat(function(d) {
//                        return monthList[d.getMonth()] + "-" + d.getFullYear();
//                    })
//                    .orient("bottom");
//
//                var yAxis = d3.svg.axis()
//                    .scale(y)
//                    .tickSize(3)
//                    .orient("left");
//
//                var line = d3.svg.line()
//                    .interpolate("basis")
//                    .x(function(d) { return x(d.time); })
//                    .y(function(d) { return y(d.count); });
//
//                // A area generator, for the dark stroke.
//                var area = d3.svg.area()
//                    .interpolate("basis")
//                    .x(function(d) { return x(d.time); })
//                    .y1(function(d) { return y(d.count); });
//
//                var svg = d3.select(ele[0]).append("svg")
//                    .attr("width", svgWidth)
//                    .attr("height", svgHeight)
//                    .append("g")
//                    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");
//
//                var tip =  d3.tip()
//                    .attr('class', 'd3-tip')
//                    .offset([-10, 0]);
//                svg.call(tip);
//
//                function processData(data) {
//                    return color.domain().map(function(name){
//                        var values = [];
//                        data.forEach(function(d){
//                            values.push({time: d.importTime, count: d[name]});
//                        })
//                        return {name: name, values: values};
//                    })
//                };
//
//                function monthDiff(d1, d2) {
//                    var months;
//                    months = (d2.getFullYear() - d1.getFullYear()) * 12;
//                    months -= d1.getMonth() + 1;
//                    months += d2.getMonth();
//                    return months <= 0 ? 0 : months;
//                };
//
//                var color = d3.scale.category10();
//
//                scope.$watch('data', function(newVals) {
//                    scope.render(newVals);
//                }, true);
//                scope.render = function (reportData) {
//                    if (!reportData)
//                        return;
//                    var _data = angular.copy(reportData);
//                    update(_data);
//                }
//
//                function update(data) {
//
//                    svg.selectAll('*').remove();
//
//                    svg.append("g")
//                        .append("text")
//                        .attr("x", width/2)
//                        .attr("y", -30)
//                        .attr("class", "header")
//                        .text("Trending Report")
//                    var i = 0;
//                    if (scope.label.teams) {
//                        i++;
//                        svg.append("g")
//                            .append("text")
//                            .attr("x", width/2)
//                            .attr("y", -10)
//                            .attr("class", "title")
//                            .text("Team: " + scope.label.teams)
//                    }
//                    if (scope.label.apps) {
//                        svg.append("g")
//                            .append("text")
//                            .attr("x", width/2)
//                            .attr("y", -10 + i*15)
//                            .attr("class", "title")
//                            .text("Application: " + scope.label.apps)
//                    }
//
//                    if (data.length === 0) {
//                        svg.append("g")
//                            .append("text")
//                            .attr("x", width/2)
//                            .attr("y", 70)
//                            .attr("class", "warning")
//                            .text("No results found")
//                        return;
//                    }
//
//                    var colorDomain = d3.keys(data[0]).filter(function(key){return key !== "importTime";});
//
//                    if (colorDomain.length === 0) {
//                        svg.append("g")
//                            .append("text")
//                            .attr("x", width/2)
//                            .attr("y", 70)
//                            .attr("class", "warning")
//                            .text("Select fields to display")
//                        return;
//                    }
//
//                    color.domain(colorDomain);
//
//                    // Add the x-axis.
//                    svg.append("g")
//                        .attr("class", "x axis")
//                        .attr("transform", "translate(0," + height + ")");
//
//                    // Add the y-axis.
//                    svg.append("g")
//                        .attr("class", "y axis");
//
//                    var rates = processData(data);
//                    var xmax = d3.max(rates, function(c) { return d3.max(c.values, function(v) { return v.time; }); });
//                    var xmin = d3.min(rates, function(c) { return d3.min(c.values, function(v) { return v.time; }); });
//                    x.domain([
//                        d3.min(rates, function(c) { return d3.min(c.values, function(v) { return v.time; }); }),
//                        d3.max(rates, function(c) { return d3.max(c.values, function(v) { return v.time; }); })
//                    ]);
//                    y.domain([
//                        d3.min(rates, function(c) { return d3.min(c.values, function(v) { return v.count; }); }),
//                        d3.max(rates, function(c) { return d3.max(c.values, function(v) { return v.count; }); })
//                    ]);
//
//                    var diffMonths = monthDiff(new Date(xmin), new Date(xmax));
//                    var intervalMonths = Math.round(diffMonths/6);
//                    intervalMonths = (intervalMonths===5 ? 4 : intervalMonths);
//                    intervalMonths = (intervalMonths>6 ? 12 : intervalMonths);
//                    xAxis.ticks(d3.time.month, intervalMonths);
//
//                    // Update the x-axis.
//                    d3.transition(svg).select('.x.axis')
//                        .call(xAxis);
//
//                    // Update y-axis.
//                    d3.transition(svg).select('.y.axis')
//                        .call(yAxis);
//
//                    // DATA JOIN
//                    var rate = svg.selectAll(".rate")
//                        .data(rates);
//
//                    // ENTER
//                    var rateEnter = rate.enter().append("g")
//                        .attr("class", "rate");
//
//                    // Add the lines.
//                    rateEnter.append("path")
//                        .attr("class", "line")
//                        .attr("d", function(d) { return line(d.values); })
//                        .style("stroke", function(d) { return color(d.name); });
//
//                    // Add the line labels in the right margin.
//                    rateEnter.append("text")
//                        .datum(function(d) { return {name: d.name, value: d.values[d.values.length - 1]}; })
//                        .attr("transform", function(d) { return "translate(" + x(d.value.time) + "," + y(d.value.count) + ")"; })
//                        .attr("x", 3)
//                        .attr("dy", ".35em")
//                        .style("font-weight", "bold")
//                        .attr('fill', function(d) { return color(d.name); })
//                        .text(function(d) { return d.name; });
//
//                    var focus = svg.append("g")
//                        .attr("class", "focus")
//                        .style("display", "none");
//
//                    var circles = focus.selectAll('circle')
//                        .data(rates)
//                        .enter()
//                        .append('circle')
//                        .attr('class', 'circle')
//                        .attr('r', 4)
//                        .attr('fill', 'none')
//                        .attr('stroke', function (d) { return color(d.name); });
//
//                    rate.append("rect")
//                        .attr("class", "overlay")
//                        .attr("width", width)
//                        .attr("height", height)
//                        .on("mouseover", function() { focus.style("display", null); })
//                        .on("mouseout", function() { focus.style("display", "none"); tip.hide()})
//                        .on("mousemove", mousemove);
//
//                    function mousemove() {
//                        var x0 = x.invert(d3.mouse(this)[0]),
//                            month = Math.round(x0);
//                        var time;
//                        var tips = [];
//                        circles.attr('transform', function (d) {
//                            var i;
//                            if (month <= d.values[0].time)
//                                i = 0;
//                            else if (month >= d.values[d.values.length-1].time) {
//                                i = d.values.length - 1;
//                            } else {
//                                for (i = 1; i< d.values.length; i++) {
//                                    if (d.values[i-1].time <= month && d.values[i].time >= month) {
//                                        i = (d.values[i].time - month > month - d.values[i-1].time) ? i-1 : i;
//                                        break;
//                                    }
//                                }
//                            }
//
//                            time = d.values[i].time;
//                            tips.push("<strong>" + d.name + ":</strong> <span style='color:red'>" + d.values[i].count + "</span>")
//                            return 'translate(' + x(d.values[i].time) + ',' + y(d.values[i].count) + ')';
//                        });
//
//                        tip.html(function(){
//                            var date = new Date(time);
//                            var tipContent = "<strong>" + "Time" + ":</strong> <span style='color:red'>" +
//                                (monthList[date.getMonth()]) + " " + date.getDate() + " " + date.getFullYear() + "</span>";
//                            tips.forEach(function(tip) {
//                                tipContent += "<br/>" + tip;
//                            })
//
//                            return tipContent;
//                        });
//                        tip.show();
//                    }
//
//                    // EXIT
//                    rate.exit().remove();
//                }
//
//                d3.select("#exportCSVButton").on('click', function(){
//                    var teamsName = (scope.label.teams) ? "_" + scope.label.teams : "";
//                    var appsName = (scope.label.apps) ? "_" + scope.label.apps : "";
//                    reportExporter.exportPDF(d3, svgWidth, svgHeight,
//                    "TrendingScans" + teamsName + appsName);
//                });
//            }
//        }
//    }]);

// Trending scans report
d3ThreadfixModule.directive('d3Trending', ['d3', 'reportExporter', 'reportUtilities', 'd3Service',
    function(d3, reportExporter, reportUtilities, d3Service) {
        return {
            restrict: 'EA',
            scope: {
                data: '=',
                label: '=',
                width: '@',
                height: '@',
                margin: '='
            },
            link: function(scope, ele, attrs) {
                var svgWidth = scope.width,
                    svgHeight = scope.height,
                    m = scope.margin,
                    w = svgWidth - m[1] - m[3],
                    h = svgHeight - m[0] - m[2];

                var
                    stackedData,
                    _data,
                    circles,
                    duration = 500;

                var x = d3.time.scale().range([0, w]),
                    y = d3.scale.linear().range([h, 0]);

                var xAxis = d3.svg.axis()
                    .scale(x)
                    .tickSize(3)
                    .tickFormat(function(d) {
                        return monthList[d.getMonth()] + "-" + d.getFullYear();
                    })
                    .orient("bottom");

                var yAxis = d3.svg.axis()
                    .scale(y)
                    .tickSize(3)
                    .orient("left");

                var color = d3.scale.category10();

                var svg = d3.select(ele[0]).append("svg")
                    .attr("width", w + m[1] + m[3])
                    .attr("height", h + m[0] + m[2])
                    .append("g")
                    .attr("transform", "translate(" + m[3] + "," + m[0] + ")");

                var monthList = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

                // A line generator, for the dark stroke.
                var line = d3.svg.line()
//                    .interpolate("basis")
                    .x(function(d) { return x(d.date); })
                    .y(function(d) { return y(d.noOfVulns); });

                // A area generator, for the dark stroke.
                var area = d3.svg.area()
//                    .interpolate("basis")
                    .x(function(d) { return x(d.date); })
                    .y1(function(d) { return y(d.noOfVulns); });

                var tip =  d3.tip()
                    .attr('class', 'd3-tip')
                    .offset([-10, 0]);

                scope.$watch('data', function(newVals) {
                    scope.render(newVals);
                }, true);
                scope.render = function (reportData) {
                    if (!reportData)
                        return;
                    _data = angular.copy(reportData);

                    svg.selectAll('*').remove();

                    if (scope.label)
                        reportUtilities.drawTitle(svg, w, scope.label.teams, scope.label.apps, "Trending Report", -30);

                    if (_data.length === 0) {
                        svg.append("g")
                            .append("text")
                            .attr("x", w/2)
                            .attr("y", 70)
                            .attr("class", "warning")
                            .text("No results found")
                        return;
                    }

                    var colorDomain = d3.keys(_data[0]).filter(function(key){return key !== "importTime";});

                    if (colorDomain.length === 0) {
                        svg.append("g")
                            .append("text")
                            .attr("x", w/2)
                            .attr("y", 70)
                            .attr("class", "warning")
                            .text("Select fields to display")
                        return;
                    }

                    color.domain(colorDomain);
                    svg.selectAll('*').remove();

                    drawReport();

                }

                function drawReport(){

                    stackedData = prepareStackedData(_data);
                    stackedData.forEach(function(s) {
                        s.maxNoOfVulns = d3.max(s.values, function(d) { return d.noOfVulns; });
                    });

                    // Sort by maximum price, descending.
                    stackedData.sort(function(a, b) { return b.maxNoOfVulns - a.maxNoOfVulns; });

                    var stack = d3.layout.stack()
                        .values(function(d) { return d.values; })
                        .x(function(d) { return d.date; })
                        .y(function(d) { return d.noOfVulns; })
                        .out(function(d, y0, y) { d.noOfVulns0 = y0; })
                        .order("reverse");

                    stack(stackedData);


                    svg.selectAll("g")
                        .data(stackedData)
                        .enter().append("g")
                        .attr("class", "symbol");

                    var xMin = d3.min(stackedData, function(d) { return d.values[0].date; });
                    var xMax = d3.max(stackedData, function(d) { return d.values[d.values.length - 1].date; });

                    // Compute the minimum and maximum date across scans.
                    x.domain([xMin, xMax]);

                    y.domain([0, d3.max(stackedData[0].values.map(function(d) { return d.noOfVulns + d.noOfVulns0; }))]);

                    var diffMonths = monthDiff(new Date(xMin), new Date(xMax)),
                        intervalMonths = Math.round(diffMonths/6);
                    intervalMonths = (intervalMonths===5 ? 4 : intervalMonths);
                    intervalMonths = (intervalMonths>6 ? 12 : intervalMonths);
                    xAxis.ticks(d3.time.month, intervalMonths);

                    var g = svg.selectAll(".symbol");

                    svg.call(tip);

                    if (scope.label)
                        reportUtilities.drawTitle(svg, w, scope.label.teams, scope.label.apps, "Trending Report", -30);

                    // Add the x-axis.
                    svg.append("g")
                        .attr("class", "x axis")
                        .attr("transform", "translate(0," + h + ")")
                        .transition()
                        .duration(duration)
                        .call(xAxis);

                    // Add the y-axis.
                    svg.append("g")
                        .attr("class", "y axis")
                        .transition()
                        .duration(duration)
                        .call(yAxis);

                    var focus = svg.append("g")
                        .attr("class", "focus")
                        .style("display", "none");

                    circles = focus.selectAll('circle')
                        .data(stackedData)
                        .enter()
                        .append('circle')
                        .attr('class', 'circle')
                        .attr('r', 4)
                        .attr('fill', 'none')
                        .attr('stroke', function (d) { return color(d.key); });

                    line
                        .y(function(d) { return y(d.noOfVulns0); });

                    area
                        .y0(function(d) { return y(d.noOfVulns0); })
                        .y1(function(d) { return y(d.noOfVulns0 + d.noOfVulns); });

                    g.each(function(d) {
                        var e = d3.select(this);

                        e.selectAll(".area")
                            .data(d3.range(1))
                            .enter().insert("path", ".line")
                            .attr("class", "area")
                            .style("fill", "white")
                            .transition()
                            .duration(duration)
                            .style("fill", color(d.key))
                            .style("fill-opacity", .5)
                            .attr("d", area(d.values));

                        e.append("path")
                            .attr("class", "line")
                            .transition()
                            .duration(duration)
                            .style("stroke-opacity", 1)
                            .attr("d", line(d.values));

                        e.append("text")
                            .attr("x", 15)
                            .attr("dy", ".35em")
                            .style("font-weight", "bold")
                            .transition()
                            .duration(duration)
                            .attr('fill', color(d.key))
                            .text(d.key)
                            .attr("transform", function() { d = d.values[d.values.length - 1]; return "translate(" + (w) + "," + y(d.noOfVulns / 2 + d.noOfVulns0) + ")"; });
                    });

                    g
                        .on("mouseover", function() { focus.style("display", null); })
                        .on("mouseout", function() { focus.style("display", "none"); tip.hide()})
                        .on("mousemove", mousemove);

                }

                d3.select("#exportCSVButton").on('click', function(){
                    var teamsName = (scope.label.teams) ? "_" + scope.label.teams : "";
                    var appsName = (scope.label.apps) ? "_" + scope.label.apps : "";
                    reportExporter.exportPDF(d3, svgWidth, svgHeight,
                            "TrendingScans" + teamsName + appsName);
                });

                function prepareStackedData(data) {
                    return color.domain().map(function(name){
                        var values = [];
                        data.forEach(function(d){
                            values.push({date: d.importTime, noOfVulns: d[name]});
                        })
                        return {key: name, values: values};
                    })
                };

                function mousemove() {
                    var x0 = x.invert(d3.mouse(this)[0]),
                        month = Math.round(x0);
                    var time;
                    var tips = [];
                    circles.attr('transform', function (d) {
                        var i;
                        if (month <= d.values[0].date)
                            i = 0;
                        else if (month >= d.values[d.values.length-1].date) {
                            i = d.values.length - 1;
                        } else {
                            for (i = 1; i< d.values.length; i++) {
                                if (d.values[i-1].date <= month && d.values[i].date >= month) {
                                    i = (d.values[i].date - month > month - d.values[i-1].date) ? i-1 : i;
                                    break;
                                }
                            }
                        }

                        time = d.values[i].date;
                        tips.push("<strong>" + d.key + ":</strong> <span style='color:red'>" + d.values[i].noOfVulns + "</span>")
                        return 'translate(' + x(d.values[i].date) + ',' + y(d.values[i].noOfVulns + d.values[i].noOfVulns0) + ')';
                    });

                    tip.html(function(){
                        var date = new Date(time);
                        var tipContent = "<strong>" + "Time" + ":</strong> <span style='color:red'>" +
                            (monthList[date.getMonth()]) + " " + date.getDate() + " " + date.getFullYear() + "</span>";
                        tips.forEach(function(tip) {
                            tipContent += "<br/>" + tip;
                        })

                        return tipContent;
                    });
                    tip.show();
                };

                function monthDiff(d1, d2) {
                    var months;
                    months = (d2.getFullYear() - d1.getFullYear()) * 12;
                    months -= d1.getMonth() + 1;
                    months += d2.getMonth();
                    return months <= 0 ? 0 : months;
                };

            }
        }
    }]);


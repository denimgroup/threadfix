var d3ThreadfixModule = angular.module('threadfix');

// Trending scans report
d3ThreadfixModule.directive('d3Trending', ['$window', '$timeout', 'd3',
    function($window, $timeout, d3) {
        return {
            restrict: 'EA',
            scope: {
                data: '=',
                label: '='
            }
            ,
            link: function(scope, ele, attrs) {
                var margin = {top: 50, right: 100, bottom: 200, left: 60},
                    width = 670 - margin.left - margin.right,
                    height = 612 - margin.top - margin.bottom;

                var x = d3.time.scale()
                    .nice(d3.time.week)
                    .range([0, width]);

                var y = d3.scale.linear()
                    .range([height, 0]);

                var monthList = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

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

                var line = d3.svg.line()
                    .x(function(d) { return x(d.time); })
                    .y(function(d) { return y(d.count); });

                var svg = d3.select(ele[0]).append("svg")
                    .attr("width", width + margin.left + margin.right)
                    .attr("height", height + margin.top + margin.bottom)
                    .append("g")
                    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

                var tip =  d3.tip()
                    .attr('class', 'd3-tip')
                    .offset([-10, 0]);
                svg.call(tip);

                function processData(data) {
                    return color.domain().map(function(name){
                        var values = [];
                        data.forEach(function(d){
                            values.push({time: d.importTime, count: d[name]});
                        })
                        return {name: name, values: values};
                    })
                };

                function monthDiff(d1, d2) {
                    var months;
                    months = (d2.getFullYear() - d1.getFullYear()) * 12;
                    months -= d1.getMonth() + 1;
                    months += d2.getMonth();
                    return months <= 0 ? 0 : months;
                };

                var color = d3.scale.category10();

                scope.$watch('data', function(newVals) {
                    scope.render(newVals);
                }, true);
                scope.render = function (reportData) {
                    if (!reportData)
                        return;
                    var _data = angular.copy(reportData);
                    update(_data);
                }

                function update(data) {

                    svg.selectAll('*').remove();

                    if (data.length === 0) {
                        svg.append("g")
                            .append("text")
                            .attr("x", width/3 + 30)
                            .attr("y", 10)
                            .style("font-size", "20px")
                            .style("font-weight", "bold")
                            .text("No results found")
                        return;
                    }

                    var colorDomain = d3.keys(data[0]).filter(function(key){return key !== "importTime";});

                    if (colorDomain.length === 0) {
                        svg.append("g")
                            .append("text")
                            .attr("x", width/3)
                            .attr("y", 10)
                            .style("font-size", "20px")
                            .style("font-weight", "bold")
                            .text("Select fields to display")
                        return;
                    }

                    color.domain(colorDomain);

                    // Add the x-axis.
                    svg.append("g")
                        .attr("class", "x axis")
                        .attr("transform", "translate(0," + height + ")");

                    // Add the y-axis.
                    svg.append("g")
                        .attr("class", "y axis");

                    var rates = processData(data);
                    var xmax = d3.max(rates, function(c) { return d3.max(c.values, function(v) { return v.time; }); });
                    var xmin = d3.min(rates, function(c) { return d3.min(c.values, function(v) { return v.time; }); });
                    x.domain([
                        d3.min(rates, function(c) { return d3.min(c.values, function(v) { return v.time; }); }),
                        d3.max(rates, function(c) { return d3.max(c.values, function(v) { return v.time; }); })
                    ]);
                    y.domain([
                        d3.min(rates, function(c) { return d3.min(c.values, function(v) { return v.count; }); }),
                        d3.max(rates, function(c) { return d3.max(c.values, function(v) { return v.count; }); })
                    ]);

                    var diffMonths = monthDiff(new Date(xmin), new Date(xmax));
                    var intervalMonths = Math.round(diffMonths/6);
                    if (intervalMonths > 6)
                        intervalMonths = 12;
                    xAxis.ticks(d3.time.month, intervalMonths);

                    // Update the x-axis.
                    d3.transition(svg).select('.x.axis')
                        .call(xAxis);

                    // Update y-axis.
                    d3.transition(svg).select('.y.axis')
                        .call(yAxis);

                    // DATA JOIN
                    var rate = svg.selectAll(".rate")
                        .data(rates);

                    // ENTER
                    var rateEnter = rate.enter().append("g")
                        .attr("class", "rate");

                    // Add the lines.
                    rateEnter.append("path")
                        .attr("class", "line")
                        .attr("d", function(d) { return line(d.values); })
                        .style("stroke", function(d) { return color(d.name); });

                    // Add the line labels in the right margin.
                    rateEnter.append("text")
                        .datum(function(d) { return {name: d.name, value: d.values[d.values.length - 1]}; })
                        .attr("transform", function(d) { return "translate(" + x(d.value.time) + "," + y(d.value.count) + ")"; })
                        .attr("x", 3)
                        .attr("dy", ".35em")
                        .style("font-weight", "bold")
                        .attr('fill', function(d) { return color(d.name); })
                        .text(function(d) { return d.name; });

                    var focus = svg.append("g")
                        .attr("class", "focus")
                        .style("display", "none");

                    var circles = focus.selectAll('circle')
                        .data(rates)
                        .enter()
                        .append('circle')
                        .attr('class', 'circle')
                        .attr('r', 4)
                        .attr('fill', 'none')
                        .attr('stroke', function (d) { return color(d.name); });

                    rate.append("rect")
                        .attr("class", "overlay")
                        .attr("width", width)
                        .attr("height", height)
                        .on("mouseover", function() { focus.style("display", null); })
                        .on("mouseout", function() { focus.style("display", "none"); tip.hide()})
                        .on("mousemove", mousemove);

                    function mousemove() {
                        var x0 = x.invert(d3.mouse(this)[0]),
                            month = Math.round(x0);
                        var time;
                        var tips = [];
                        circles.attr('transform', function (d) {
                            var i;
                            if (month <= d.values[0].time)
                                i = 0;
                            else if (month >= d.values[d.values.length-1].time) {
                                i = d.values.length - 1;
                            } else {
                                for (i = 1; i< d.values.length; i++) {
                                    if (d.values[i-1].time <= month && d.values[i].time >= month) {
                                        i = (d.values[i].time - month > month - d.values[i-1].time) ? i-1 : i;
                                        break;
                                    }
                                }
                            }

                            time = d.values[i].time;
                            tips.push("<strong>" + d.name + ":</strong> <span style='color:red'>" + d.values[i].count + "</span>")
                            return 'translate(' + x(d.values[i].time) + ',' + y(d.values[i].count) + ')';
                        });

                        tip.html(function(){
                            var date = new Date(time);
                            var tipContent = "<strong>" + "Time" + ":</strong> <span style='color:red'>" +
                                (date.getMonth() + 1) + "/" + date.getDate() + "/" + date.getFullYear() + "</span>";
                            tips.forEach(function(tip) {
                                tipContent += "<br/>" + tip;
                            })

                            return tipContent;
                        });
                        tip.show();
                    }

                    // EXIT
                    rate.exit().remove();
                }
            }
        }
    }]);


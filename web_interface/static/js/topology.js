// Configure Socket.IO
const socket = io({
    transports: ['websocket'],  // Force WebSocket only
    upgrade: false,             // Disable transport upgrade
    reconnection: true,         // Enable reconnection
    reconnectionAttempts: Infinity,  // Infinite retry attempts
    reconnectionDelay: 1000,    // Reconnection delay in ms
    timeout: 5000              // Connection timeout
});

// Traffic monitoring variables
let trafficDisplay = false;
let maxThroughput = 1000000; // Default 1 Mbps for scaling

// Update throttling variables
let isUpdating = false;
let pendingUpdate = false;
let lastUpdateTime = 0;
const UPDATE_THROTTLE_MS = 1000; // Minimum 1 second between updates

// Create force-directed graph layout
let svg = d3.select('#network svg');
let width = svg.node().getBoundingClientRect().width;
let height = svg.node().getBoundingClientRect().height;
let simulation;

// Calculate center position considering title height
let centerY = height * 0.4;
let centerX = width * 0.5;

// Create arrow marker
svg.append('defs').append('marker')
    .attr('id', 'arrowhead')
    .attr('viewBox', '-10 -10 20 20')
    .attr('refX', 25)
    .attr('refY', 0)
    .attr('markerWidth', 6)
    .attr('markerHeight', 6)
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M-6.75,-6.75 L 0,0 L -6.75,6.75')
    .attr('fill', '#666');

// Create zoom behavior
const zoom = d3.zoom()
    .scaleExtent([0.2, 2])
    .on('zoom', (event) => {
        container.attr('transform', event.transform);
    });

svg.call(zoom);

// Create container group
const container = svg.append('g')
    .attr('transform', `translate(${centerX},${centerY})`);

// Create tooltip
const tooltip = d3.select('#network')
    .append('div')
    .attr('class', 'tooltip')
    .style('opacity', 0);

// Initialize force simulation
function initSimulation() {
    simulation = d3.forceSimulation()
        .force('link', d3.forceLink().id(d => d.id).distance(200))
        .force('charge', d3.forceManyBody()
            .strength(-2000)
            .distanceMin(100)
            .distanceMax(500)
        )
        .force('center', d3.forceCenter(0, 0)) // Use container-relative center
        .force('collision', d3.forceCollide().radius(80))
        .force('x', d3.forceX(0).strength(0.1)) // Add X-axis force
        .force('y', d3.forceY(0).strength(0.1)) // Add Y-axis force
        .alphaDecay(0.05)
        .velocityDecay(0.2);
}

// Drag behavior
function drag(simulation) {
    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
        d3.select(this).classed('dragging', true);
    }

    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }

    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
        d3.select(this).classed('dragging', false);
    }

    return d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended);
}

// Update topology visualization
function updateTopology(data) {
    if (!data || !data.topology) {
        console.warn('Invalid topology data received');
        return;
    }
    
    // Throttle updates to prevent excessive refreshing
    const currentTime = Date.now();
    if (isUpdating) {
        pendingUpdate = true;
        return;
    }
    
    if (currentTime - lastUpdateTime < UPDATE_THROTTLE_MS) {
        // Schedule delayed update
        if (!pendingUpdate) {
            pendingUpdate = true;
            setTimeout(() => {
                if (pendingUpdate) {
                    pendingUpdate = false;
                    updateTopology(data);
                }
            }, UPDATE_THROTTLE_MS - (currentTime - lastUpdateTime));
        }
        return;
    }
    
    isUpdating = true;
    lastUpdateTime = currentTime;
    
    const topology = data.topology;
    let nodes = [];
    const links = [];
    const processedNodes = new Set();
    
    try {
        // Add switch nodes
        if (Array.isArray(topology.switches)) {
            topology.switches.forEach(sw => {
                if (sw && sw.dpid) {
                    const nodeId = `s${sw.dpid}`;
                    if (!processedNodes.has(nodeId)) {
                        const existingNode = simulation ? simulation.nodes().find(n => n.id === nodeId) : null;
                        nodes.push({
                            id: nodeId,
                            label: `Switch ${sw.dpid}`,
                            type: 'switch',
                            title: `Switch ${sw.dpid}\nPorts: ${Array.isArray(sw.ports) ? sw.ports.length : 0}`,
                            x: existingNode ? existingNode.x : undefined,
                            y: existingNode ? existingNode.y : undefined,
                            vx: existingNode ? existingNode.vx : undefined,
                            vy: existingNode ? existingNode.vy : undefined
                        });
                        processedNodes.add(nodeId);
                    }
                }
            });
        }
        
        // Add host nodes
        if (Array.isArray(topology.hosts)) {
            topology.hosts.forEach(host => {
                const isValidIP = host.ip && 
                                host.ip !== 'unknown' && 
                                host.ip !== 'Unknown IP' &&
                                host.ip !== '10.0.0.254' &&
                                /^(\d{1,3}\.){3}\d{1,3}$/.test(host.ip);

                if (isValidIP && host.mac && !processedNodes.has(host.mac)) {
                    const existingNode = simulation ? simulation.nodes().find(n => n.id === host.mac) : null;
                    const nodeData = {
                        id: host.mac,
                        label: `Host\n${host.ip}`,
                        type: 'host',
                        title: `MAC: ${host.mac}\nIP: ${host.ip}`,
                        switchId: host.dpid ? `s${host.dpid}` : null,
                        ip: host.ip,
                        x: existingNode ? existingNode.x : undefined,
                        y: existingNode ? existingNode.y : undefined,
                        vx: existingNode ? existingNode.vx : undefined,
                        vy: existingNode ? existingNode.vy : undefined
                    };
                    
                    // Add traffic information if available
                    if (host.traffic) {
                        nodeData.traffic = host.traffic;
                    }
                    
                    nodes.push(nodeData);
                    processedNodes.add(host.mac);
                }
            });
        }

        // Add inter-switch links
        if (Array.isArray(topology.links)) {
            topology.links.forEach(link => {
                if (link && link.src && link.dst && link.src.dpid && link.dst.dpid) {
                    const linkData = {
                        source: `s${link.src.dpid}`,
                        target: `s${link.dst.dpid}`,
                        title: `Port ${link.src.port_no} -> Port ${link.dst.port_no}`,
                        type: 'switch-switch'
                    };
                    
                    // Add traffic information if available
                    if (link.total_throughput !== undefined) {
                        linkData.total_throughput = link.total_throughput;
                    }
                    
                    links.push(linkData);
                }
            });
        }
        
        // Add host connections
        if (Array.isArray(topology.hosts)) {
            topology.hosts.forEach(host => {
                const isValidIP = host.ip && 
                                host.ip !== 'unknown' && 
                                host.ip !== 'Unknown IP' &&
                                host.ip !== '10.0.0.254' &&
                                /^(\d{1,3}\.){3}\d{1,3}$/.test(host.ip);

                if (isValidIP && host.mac && host.dpid) {
                    const linkData = {
                        source: host.mac,
                        target: `s${host.dpid}`,
                        title: `Port ${host.port || 'unknown'}`,
                        type: 'host-switch'
                    };
                    
                    // Add traffic information if available
                    if (host.traffic) {
                        const hostThroughput = (host.traffic.rx_throughput || 0) + (host.traffic.tx_throughput || 0);
                        linkData.total_throughput = hostThroughput;
                    }
                    
                    links.push(linkData);
                }
            });
        }

        // Update force simulation
        if (!simulation) {
            initSimulation();
        }

        // Update global max throughput for scaling
        updateMaxThroughput(topology);

        // Update links
        const link = container.selectAll('.link')
            .data(links, d => `${d.source}-${d.target}`);

        // Remove obsolete links
        link.exit().transition()
            .duration(200)
            .style('opacity', 0)
            .remove();

        // Add new links
        const linkEnter = link.enter()
            .append('path')
            .attr('class', 'link')
            .attr('marker-end', 'url(#arrowhead)')
            .style('opacity', 0)
            .style('stroke', '#666')
            .style('stroke-width', 2)
            .style('fill', 'none')
            .transition()
            .duration(200)
            .style('opacity', 1);

        // Update nodes
        const node = container.selectAll('.node')
            .data(nodes, d => d.id);

        // Remove obsolete nodes
        node.exit().transition()
            .duration(200)
            .style('opacity', 0)
            .remove();

        // Add new nodes
        const nodeEnter = node.enter()
            .append('g')
            .attr('class', d => `node ${d.type}`)
            .style('opacity', 0)
            .call(drag(simulation));

        // Add switch node graphics
        nodeEnter.filter(d => d.type === 'switch')
            .append('circle')
            .attr('r', 25);

        // Add host node graphics
        nodeEnter.filter(d => d.type === 'host')
            .append('rect')
            .attr('width', 50)
            .attr('height', 50)
            .attr('x', -25)
            .attr('y', -25);

        // Add node labels
        nodeEnter.append('text')
            .text(d => d.label)
            .attr('dy', d => d.type === 'host' ? 35 : 35);

        // Fade in new nodes
        nodeEnter.transition()
            .duration(200)
            .style('opacity', 1);

        // Update all nodes (existing and new) text and titles
        container.selectAll('.node').each(function(d) {
            d3.select(this).select('text')
                .text(d => d.label);
            
            d3.select(this).selectAll('title').remove();
            d3.select(this).append('title').text(d.title);
            
            d3.select(this)
                .on('mouseover', (event, d) => {
                    tooltip.transition()
                        .duration(200)
                        .style('opacity', .9);
                    tooltip.html(d.title)
                        .style('left', (event.pageX + 10) + 'px')
                        .style('top', (event.pageY - 28) + 'px');
                })
                .on('mouseout', () => {
                    tooltip.transition()
                        .duration(500)
                        .style('opacity', 0);
                });
        });

        // Update simulation
        simulation.nodes(nodes);
        simulation.force('link').links(links);
        
        // Update traffic visualization after nodes and links are updated
        setTimeout(() => {
            updateTrafficVisualization();
        }, 100);
        
        // Restart simulation with lower alpha to reduce oscillation
        simulation.alpha(0.1).restart();
        
        // Update tick event handler
        simulation.on('tick', () => {
            // Constrain node positions within view bounds
            const padding = 50;
            const bounds = {
                x1: -width/2 + padding,
                x2: width/2 - padding,
                y1: -height/2 + padding,
                y2: height/2 - padding
            };

            nodes.forEach(d => {
                d.x = Math.max(bounds.x1, Math.min(bounds.x2, d.x));
                d.y = Math.max(bounds.y1, Math.min(bounds.y2, d.y));
            });

            // Update link positions
            container.selectAll('.link')
                .attr('d', d => {
                    const dx = d.target.x - d.source.x;
                    const dy = d.target.y - d.source.y;
                    const dr = Math.sqrt(dx * dx + dy * dy) * 2;
                    return `M${d.source.x},${d.source.y}A${dr},${dr} 0 0,1 ${d.target.x},${d.target.y}`;
                });

            // Update node positions
            container.selectAll('.node')
                .attr('transform', d => `translate(${d.x},${d.y})`);
        });

    } catch (error) {
        console.error('Error updating topology:', error);
    } finally {
        // Reset update throttling flag
        isUpdating = false;
        
        // Process pending update if any
        if (pendingUpdate) {
            pendingUpdate = false;
            setTimeout(() => requestTopologyUpdate(), 100);
        }
    }
}

// Handle window resize
window.addEventListener('resize', () => {
    width = svg.node().getBoundingClientRect().width;
    height = svg.node().getBoundingClientRect().height;
    centerY = height * 0.4;
    centerX = width * 0.5;
    
    if (simulation) {
        simulation.force('center', d3.forceCenter(0, 0));
        container.attr('transform', `translate(${centerX},${centerY})`);
        simulation.alpha(0.3).restart();
    }
});

// Listen for topology updates
socket.on('topology_update', (data) => {
    if (!data || !data.topology) {
        console.warn('Received invalid topology data');
        return;
    }
    
    // Use throttled update for WebSocket events too
    updateTopology(data);
});

// Listen for heartbeat - reduce frequency
socket.on('heartbeat', (data) => {
    // Only request update every few heartbeats to reduce load
    if (Math.random() < 0.3) { // 30% chance to update on heartbeat
        requestTopologyUpdate();
    }
});

// Connection established handler
socket.on('connect', () => {
    requestTopologyUpdate();
});

// Connection lost handler
socket.on('disconnect', () => {
    clearTopology();
});

function clearTopology() {
    container.selectAll('.link').remove();
    container.selectAll('.node').remove();
    if (simulation) {
        simulation.stop();
        simulation = null;
    }
}

let lastRequestTime = 0;
const MIN_REQUEST_INTERVAL = 100;

function requestTopologyUpdate() {
    const now = Date.now();
    if (socket.connected && now - lastRequestTime >= MIN_REQUEST_INTERVAL) {
        socket.emit('request_topology');
        lastRequestTime = now;
    }
}

// Set reasonable polling interval (reduced from 200ms to 2000ms)
const updateInterval = setInterval(requestTopologyUpdate, 2000);

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    clearInterval(updateInterval);
    if (simulation) {
        simulation.stop();
    }
});

// Request update when page becomes visible
document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
        requestTopologyUpdate();
    }
});

// Network online handler
window.addEventListener('online', () => {
    requestTopologyUpdate();
});

// Initialize view position
svg.call(zoom.transform, d3.zoomIdentity.translate(centerX, centerY).scale(0.6));

// Traffic monitoring functions
function updateMaxThroughput(topology) {
    let currentMax = 0;
    
    // Check link throughput
    if (Array.isArray(topology.links)) {
        topology.links.forEach(link => {
            if (link.total_throughput) {
                currentMax = Math.max(currentMax, link.total_throughput);
            }
        });
    }
    
    // Check host throughput
    if (Array.isArray(topology.hosts)) {
        topology.hosts.forEach(host => {
            if (host.traffic) {
                const hostThroughput = (host.traffic.rx_throughput || 0) + (host.traffic.tx_throughput || 0);
                currentMax = Math.max(currentMax, hostThroughput);
            }
        });
    }
    
    // Update max throughput for scaling (with minimum threshold)
    maxThroughput = Math.max(currentMax, 1000000); // At least 1 Mbps
}

function formatThroughput(throughput) {
    if (throughput >= 1000000000) {
        return `${(throughput / 1000000000).toFixed(2)} Gbps`;
    } else if (throughput >= 1000000) {
        return `${(throughput / 1000000).toFixed(2)} Mbps`;
    } else if (throughput >= 1000) {
        return `${(throughput / 1000).toFixed(2)} Kbps`;
    } else {
        return `${throughput.toFixed(2)} bps`;
    }
}

function getTrafficColor(throughput) {
    // Color gradient from green (low) to red (high)
    const ratio = Math.min(throughput / maxThroughput, 1);
    const red = Math.floor(255 * ratio);
    const green = Math.floor(255 * (1 - ratio));
    return `rgb(${red}, ${green}, 0)`;
}

function getTrafficWidth(throughput) {
    // Scale line width based on throughput (1px to 10px)
    const ratio = Math.min(throughput / maxThroughput, 1);
    return Math.max(1, ratio * 8) + 1;
}

function toggleTrafficDisplay() {
    trafficDisplay = !trafficDisplay;
    const button = document.getElementById('traffic-toggle');
    if (button) {
        button.textContent = trafficDisplay ? 'Hide Traffic' : 'Show Traffic';
        button.className = trafficDisplay ? 'btn btn-warning' : 'btn btn-success';
    }
    
    // Update visualization
    updateTrafficVisualization();
}

function updateTrafficVisualization() {
    // Update link colors and widths based on traffic
    container.selectAll('.link')
        .style('stroke', function(d) {
            if (trafficDisplay && d.total_throughput) {
                return getTrafficColor(d.total_throughput);
            }
            return '#666';
        })
        .style('stroke-width', function(d) {
            if (trafficDisplay && d.total_throughput) {
                return getTrafficWidth(d.total_throughput);
            }
            return 2;
        });
    
    // Update node colors based on traffic
    container.selectAll('.node')
        .style('fill', function(d) {
            if (trafficDisplay && d.type === 'host' && d.traffic) {
                const hostThroughput = (d.traffic.rx_throughput || 0) + (d.traffic.tx_throughput || 0);
                if (hostThroughput > 0) {
                    return getTrafficColor(hostThroughput);
                }
            }
            return d.type === 'switch' ? '#4682b4' : '#ff6b6b';
        });
}

function showTrafficStats() {
    // Create traffic statistics panel
    const statsPanel = document.getElementById('traffic-stats');
    if (!statsPanel) {
        const panel = document.createElement('div');
        panel.id = 'traffic-stats';
        panel.className = 'traffic-stats-panel';
        panel.style.cssText = `
            position: fixed;
            top: 50px;
            right: 20px;
            width: 300px;
            background: white;
            border: 1px solid #ccc;
            border-radius: 5px;
            padding: 15px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            z-index: 1000;
            display: none;
        `;
        panel.innerHTML = `
            <h3 style="margin-top: 0;">Traffic Statistics</h3>
            <div id="stats-content">Loading...</div>
            <button onclick="hideTrafficStats()" style="margin-top: 10px; padding: 5px 10px;">Close</button>
        `;
        document.body.appendChild(panel);
    }
    
    // Fetch and display traffic statistics
    fetch('/traffic/summary')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            const content = document.getElementById('stats-content');
            if (content) {
                if (data.error) {
                    content.innerHTML = `<p style="color: red;">Error: ${data.error}</p>`;
                } else {
                    content.innerHTML = `
                        <p><strong>Total Throughput:</strong> ${formatThroughput(data.total_throughput || 0)}</p>
                        <p><strong>Total Packets:</strong> ${(data.total_packets || 0).toLocaleString()}</p>
                        <p><strong>Total Bytes:</strong> ${(data.total_bytes || 0).toLocaleString()}</p>
                        <p><strong>Active Switches:</strong> ${data.num_switches || 0}</p>
                        <p><strong>Active Flows:</strong> ${data.num_flows || 0}</p>
                        <p><strong>Last Updated:</strong> ${new Date((data.timestamp || Date.now() / 1000) * 1000).toLocaleString()}</p>
                    `;
                }
            }
        })
        .catch(error => {
            console.error('Error fetching traffic statistics:', error);
            const content = document.getElementById('stats-content');
            if (content) {
                content.innerHTML = `
                    <p style="color: red;">Failed to load traffic statistics</p>
                    <p style="font-size: 12px; color: #666;">
                        Make sure the Ryu controller is running on port 8080 and the traffic monitoring features are enabled.
                    </p>
                    <p style="font-size: 12px; color: #666;">Error: ${error.message}</p>
                `;
            }
        });
    
    statsPanel.style.display = 'block';
}

function hideTrafficStats() {
    const statsPanel = document.getElementById('traffic-stats');
    if (statsPanel) {
        statsPanel.style.display = 'none';
    }
}
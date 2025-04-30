// Configure Socket.IO
const socket = io({
    transports: ['websocket'],  // Force WebSocket only
    upgrade: false,             // Disable transport upgrade
    reconnection: true,         // Enable reconnection
    reconnectionAttempts: Infinity,  // Infinite retry attempts
    reconnectionDelay: 1000,    // Reconnection delay in ms
    timeout: 5000              // Connection timeout
});

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
                    nodes.push(nodeData);
                    processedNodes.add(host.mac);
                }
            });
        }

        // Add inter-switch links
        if (Array.isArray(topology.links)) {
            topology.links.forEach(link => {
                if (link && link.src && link.dst && link.src.dpid && link.dst.dpid) {
                    links.push({
                        source: `s${link.src.dpid}`,
                        target: `s${link.dst.dpid}`,
                        title: `Port ${link.src.port_no} -> Port ${link.dst.port_no}`
                    });
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
                    links.push({
                        source: host.mac,
                        target: `s${host.dpid}`,
                        title: `Port ${host.port || 'unknown'}`
                    });
                }
            });
        }

        // Update force simulation
        if (!simulation) {
            initSimulation();
        }

        // Update links
        const link = container.selectAll('.link')
            .data(links, d => `${d.source}-${d.target}`);

        // Remove obsolete links
        link.exit().transition()
            .duration(500)
            .style('opacity', 0)
            .remove();

        // Add new links
        const linkEnter = link.enter()
            .append('path')
            .attr('class', 'link')
            .attr('marker-end', 'url(#arrowhead)')
            .style('opacity', 0)
            .transition()
            .duration(500)
            .style('opacity', 1);

        // Update nodes
        const node = container.selectAll('.node')
            .data(nodes, d => d.id);

        // Remove obsolete nodes
        node.exit().transition()
            .duration(500)
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
            .duration(500)
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
        
        // Restart simulation with lower alpha
        simulation.alpha(0.3).restart();
        
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
    
    requestAnimationFrame(() => {
        updateTopology(data);
    });
});

// Listen for heartbeat
socket.on('heartbeat', (data) => {
    requestTopologyUpdate();
});

// Connection established handler
socket.on('connect', () => {
    console.log('WebSocket connection established');
    requestTopologyUpdate();
});

// Connection lost handler
socket.on('disconnect', () => {
    console.log('WebSocket connection lost');
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

// Set shorter polling interval
const updateInterval = setInterval(requestTopologyUpdate, 200);

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
    console.log('Network connection restored');
    requestTopologyUpdate();
});

// Initialize view position
svg.call(zoom.transform, d3.zoomIdentity.translate(centerX, centerY).scale(0.6));
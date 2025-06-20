document.addEventListener('DOMContentLoaded', function() {
    // Renamed elements for clarity and consistency with HTML
    const startCaptureBtn = document.getElementById('startCaptureBtn');
    const stopCaptureBtn = document.getElementById('stopCaptureBtn');
    const clearPacketsBtn = document.getElementById('clearPacketsBtn');
    const interfaceInput = document.getElementById('interface');
    const bpfFilterInput = document.getElementById('bpfFilter');
    const domainFilterInput = document.getElementById('domainFilter');
    const searchBar = document.getElementById('searchBar');
    const captureStatusSpan = document.getElementById('captureStatus');
    const packetTableBody = document.getElementById('packetTableBody');
    const flaggedPacketTableBody = document.getElementById('flaggedPacketTableBody');

    // NEW: PCAP file upload elements
    const pcapFileInput = document.getElementById('pcapFile');
    const uploadPcapBtn = document.getElementById('uploadPcapBtn');

    let packetFetchInterval;
    let flaggedPacketFetchInterval;
    let allDisplayedPackets = [];
    let currentPacketCount = 0;
    let currentFlaggedPacketCount = 0;

    // --- NEW: Function to update button and input states based on backend status ---
    function updateCombinedButtonStates(status) {
        const isCapturing = status.is_capturing;
        const isAnalyzingPcap = status.is_analyzing_pcap;
        const isActive = isCapturing || isAnalyzingPcap;

        // Disable/enable controls based on overall activity
        startCaptureBtn.disabled = isActive;
        uploadPcapBtn.disabled = isActive;
        stopCaptureBtn.disabled = !isActive;
        clearPacketsBtn.disabled = isActive; // Prevent clearing data during active operation

        // Input fields for live capture and domain filter
        interfaceInput.disabled = isActive;
        bpfFilterInput.disabled = isActive;
        domainFilterInput.disabled = isActive;

        // PCAP file input
        pcapFileInput.disabled = isActive;

        // Search bar
        searchBar.disabled = isActive && allDisplayedPackets.length === 0;

        // Status message
        if (isCapturing) {
            captureStatusSpan.textContent = "Capturing Live Traffic...";
            captureStatusSpan.className = "status-message active"; // Add a class for styling
        } else if (isAnalyzingPcap) {
            captureStatusSpan.textContent = "Analyzing PCAP File...";
            captureStatusSpan.className = "status-message active"; // Add a class for styling
        } else {
            captureStatusSpan.textContent = "Inactive";
            captureStatusSpan.className = "status-message inactive"; // Add a class for styling
        }
    }

    // --- Main Packet Table Rendering ---
    function renderMainTable(packetsToDisplay) {
        packetTableBody.innerHTML = ''; // Clear existing rows
        packetsToDisplay.forEach(packet => {
            const row = packetTableBody.insertRow(-1); // Insert at the bottom

            // Apply CSS classes based on flag types for the main table
            if (packet.is_targeted_flagged) {
                row.classList.add('flagged-packet'); // For targeted website traffic
            }
            if (packet.is_intrusion_flagged) {
                row.classList.add('intrusion-flagged-packet'); // For intrusion detection
            }
            
            // Set tooltip with combined reasons for the main table
            let allReasons = [];
            if (packet.is_targeted_flagged) {
                allReasons.push("Targeted: " + packet.targeted_reasons.join("; "));
            }
            if (packet.is_intrusion_flagged) {
                allReasons.push("Intrusion: " + packet.intrusion_reasons.join("; "));
            }
            if (allReasons.length > 0) {
                row.title = allReasons.join("\n");
            }

            // Populate cells for the main table
            row.insertCell(0).textContent = packet.timestamp;
            row.insertCell(1).textContent = packet.src_ip;
            row.insertCell(2).textContent = packet.dst_ip;
            row.insertCell(3).textContent = packet.protocol;
            row.insertCell(4).textContent = packet.length;
            row.insertCell(5).textContent = packet.summary;
            row.insertCell(6).textContent = packet.raw_payload; // Payload preview
            
            const flaggedStatusCell = row.insertCell(7);
            let flagText = "";
            if (packet.is_targeted_flagged && packet.is_intrusion_flagged) {
                flagText = "Both";
            } else if (packet.is_targeted_flagged) {
                flagText = "Targeted";
            } else if (packet.is_intrusion_flagged) {
                flagText = "Intrusion";
            } else {
                flagText = "No";
            }
            flaggedStatusCell.textContent = flagText;
        });
    }

    // --- Flagged Packet Table Rendering ---
    function renderFlaggedTable(packetsToDisplay) {
        flaggedPacketTableBody.innerHTML = ''; // Clear existing rows
        packetsToDisplay.forEach(packet => {
            const row = flaggedPacketTableBody.insertRow(0); // Insert at the top (most recent first)

            // Apply CSS classes specific to the flagged table (can be the same or different)
            if (packet.is_targeted_flagged) {
                row.classList.add('flagged-packet');
            }
            if (packet.is_intrusion_flagged) {
                row.classList.add('intrusion-flagged-packet');
            }

            // Populate cells for the flagged table
            row.insertCell(0).textContent = packet.timestamp;
            row.insertCell(1).textContent = packet.src_ip;
            row.insertCell(2).textContent = packet.dst_ip;
            row.insertCell(3).textContent = packet.protocol;
            row.insertCell(4).textContent = packet.summary;

            // Combine and display the reasons directly in the flagged log
            let combinedReasons = [];
            if (packet.is_targeted_flagged && packet.targeted_reasons.length > 0) {
                combinedReasons.push('Targeted: ' + packet.targeted_reasons.join('; '));
            }
            if (packet.is_intrusion_flagged && packet.intrusion_reasons.length > 0) {
                combinedReasons.push('Intrusion: ' + packet.intrusion_reasons.join('; '));
            }
            row.insertCell(5).textContent = combinedReasons.join(' | '); // Display all reasons
        });
    }

    // --- Fetch All Packets (for main table) ---
    function fetchPackets() {
        fetch('/get_packets')
            .then(response => response.json())
            .then(packets => {
                // Only update if there are new packets or the table was cleared
                if (packets.length > currentPacketCount || (currentPacketCount > 0 && packets.length === 0)) {
                    // Get only the new packets since the last fetch
                    const newPackets = packets.slice(currentPacketCount);
                    // Add new packets to the beginning (for reverse order display)
                    allDisplayedPackets = [...newPackets.reverse(), ...allDisplayedPackets]; 
                    
                    // Keep the display buffer size limited (e.g., to MAX_PACKETS_DISPLAY set in Flask)
                    if (allDisplayedPackets.length > 1000) { // Should match Flask's MAX_PACKETS_DISPLAY
                        allDisplayedPackets = allDisplayedPackets.slice(0, 1000);
                    }

                    currentPacketCount = packets.length; // Update the total count
                    filterAndRenderMainPackets(); // Re-render the main table with new data
                }
            })
            .catch(error => console.error('Error fetching all packets:', error));
    }

    // --- Fetch Flagged Packets (for flagged log table) ---
    function fetchFlaggedPackets() {
        fetch('/get_flagged_packets')
            .then(response => response.json())
            .then(packets => {
                // Only update if there are new flagged packets or the table was cleared
                if (packets.length > currentFlaggedPacketCount || (currentFlaggedPacketCount > 0 && packets.length === 0)) {
                    renderFlaggedTable(packets); // Render all current flagged packets
                    currentFlaggedPacketCount = packets.length; // Update flagged count
                }
            })
            .catch(error => console.error('Error fetching flagged packets:', error));
    }

    // --- Search/Filter for Main Packet Table ---
    function filterAndRenderMainPackets() {
        const searchTerm = searchBar.value.toLowerCase().trim();
        let filtered = [];

        if (searchTerm === '') {
            filtered = allDisplayedPackets;
        } else {
            filtered = allDisplayedPackets.filter(packet => {
                const matchesSrcIp = packet.src_ip.toLowerCase().includes(searchTerm);
                const matchesDstIp = packet.dst_ip.toLowerCase().includes(searchTerm);
                const matchesProtocol = packet.protocol.toLowerCase().includes(searchTerm);
                const matchesSummary = packet.summary.toLowerCase().includes(searchTerm);
                const matchesRawPayload = packet.raw_payload.toLowerCase().includes(searchTerm);

                // Include search in flag reasons
                const matchesTargetedReason = packet.is_targeted_flagged && packet.targeted_reasons.some(reason => reason.toLowerCase().includes(searchTerm));
                const matchesIntrusionReason = packet.is_intrusion_flagged && packet.intrusion_reasons.some(reason => reason.toLowerCase().includes(searchTerm));

                return matchesSrcIp || matchesDstIp || matchesProtocol || 
                       matchesSummary || matchesRawPayload || matchesTargetedReason || matchesIntrusionReason;
            });
        }
        renderMainTable(filtered); // Render the filtered results to the main table
    }

    // --- Initial Load Logic ---
    fetch('/get_status')
        .then(response => response.json())
        .then(data => {
            updateCombinedButtonStates(data); // Use the new function
            if (data.is_capturing || data.is_analyzing_pcap) {
                // Start both fetching intervals if any operation is active
                packetFetchInterval = setInterval(fetchPackets, 1000); // Main packets
                flaggedPacketFetchInterval = setInterval(fetchFlaggedPackets, 1000); // Flagged log
            }
            fetchPackets(); // Initial fetch for main packets
            fetchFlaggedPackets(); // Initial fetch for flagged packets
        })
        .catch(error => console.error('Error fetching initial status:', error));

    // --- Event Listeners ---

    // Start Capture button event
    startCaptureBtn.addEventListener('click', function() {
        const interfaceVal = interfaceInput.value;
        const bpfFilterVal = bpfFilterInput.value;
        const domainFilterVal = domainFilterInput.value;

        fetch('/start_capture', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `interface=${encodeURIComponent(interfaceVal)}&filter=${encodeURIComponent(bpfFilterVal)}&domain_filter=${encodeURIComponent(domainFilterVal)}`
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            if (data.status === 'success') {
                updateCombinedButtonStates({ is_capturing: true, is_analyzing_pcap: false });
                // Reset counts and clear display on new capture start
                currentPacketCount = 0;
                currentFlaggedPacketCount = 0;
                allDisplayedPackets = [];
                packetTableBody.innerHTML = '';
                flaggedPacketTableBody.innerHTML = '';
                searchBar.value = '';
                
                // Clear any existing intervals and start new ones
                clearInterval(packetFetchInterval);
                clearInterval(flaggedPacketFetchInterval);
                packetFetchInterval = setInterval(fetchPackets, 1000);
                flaggedPacketFetchInterval = setInterval(fetchFlaggedPackets, 1000);
            } else {
                // If starting fails, fetch current status to correctly update UI
                fetch('/get_status')
                    .then(res => res.json())
                    .then(status => updateCombinedButtonStates(status));
            }
        })
        .catch(error => {
            console.error('Error starting capture:', error);
            alert('Failed to start capture due to a network or server error.');
            // Fetch status to ensure UI is correct after error
            fetch('/get_status')
                .then(res => res.json())
                .then(status => updateCombinedButtonStates(status));
        });
    });

    // Stop Capture button event
    stopCaptureBtn.addEventListener('click', function() {
        fetch('/stop_capture', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            if (data.status === 'success') {
                updateCombinedButtonStates({ is_capturing: false, is_analyzing_pcap: false });
                // Clear both intervals
                clearInterval(packetFetchInterval);
                clearInterval(flaggedPacketFetchInterval);
                // Re-render to ensure final state is shown after stop
                filterAndRenderMainPackets();
                fetchFlaggedPackets(); // Fetch final flagged packets to display
            } else {
                // If stopping fails, fetch current status to correctly update UI
                fetch('/get_status')
                    .then(res => res.json())
                    .then(status => updateCombinedButtonStates(status));
            }
        })
        .catch(error => {
            console.error('Error stopping capture:', error);
            alert('Failed to stop capture due to a network or server error.');
            fetch('/get_status')
                .then(res => res.json())
                .then(status => updateCombinedButtonStates(status));
        });
    });

    // Clear All Displayed Packets button event
    clearPacketsBtn.addEventListener('click', function() {
        fetch('/clear_packets', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                if (data.status === 'success') {
                    allDisplayedPackets = [];
                    currentPacketCount = 0;
                    currentFlaggedPacketCount = 0;
                    packetTableBody.innerHTML = '';
                    flaggedPacketTableBody.innerHTML = '';
                    searchBar.value = ''; // Clear search bar too
                    // After clearing, fetch status to ensure button states are correct
                    fetch('/get_status')
                        .then(res => res.json())
                        .then(status => updateCombinedButtonStates(status));
                }
            })
            .catch(error => console.error('Error clearing packets:', error));
    });

    // NEW: Upload PCAP button event
    uploadPcapBtn.addEventListener('click', function() {
        const pcapFile = pcapFileInput.files[0];
        const domainFilterVal = domainFilterInput.value;

        if (!pcapFile) {
            alert('Please select a PCAP file to upload.');
            return;
        }

        const formData = new FormData();
        formData.append('pcap_file', pcapFile);
        formData.append('domain_filter', domainFilterVal); // Pass domain filter to backend

        // Set status and disable controls immediately
        updateCombinedButtonStates({ is_capturing: false, is_analyzing_pcap: true });
        // Clear previous data before starting new analysis on UI
        currentPacketCount = 0;
        currentFlaggedPacketCount = 0;
        allDisplayedPackets = [];
        packetTableBody.innerHTML = '';
        flaggedPacketTableBody.innerHTML = '';
        searchBar.value = '';

        // Clear any existing intervals and start new ones for polling results
        clearInterval(packetFetchInterval);
        clearInterval(flaggedPacketFetchInterval);
        packetFetchInterval = setInterval(fetchPackets, 1000);
        flaggedPacketFetchInterval = setInterval(fetchFlaggedPackets, 1000);

        fetch('/upload_pcap', {
            method: 'POST',
            body: formData // FormData automatically sets 'Content-Type': 'multipart/form-data'
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            if (data.status === 'success' || data.status === 'analysis_started') {
                // Backend initiated analysis, UI will update via polling intervals
                // No explicit updateCombinedButtonStates here, as polling handles it
            } else {
                // If upload/analysis fails, fetch current status to correctly update UI
                fetch('/get_status')
                    .then(res => res.json())
                    .then(status => updateCombinedButtonStates(status));
            }
        })
        .catch(error => {
            console.error('Error uploading PCAP:', error);
            alert('Failed to upload and analyze PCAP file due to a network or server error.');
            // Fetch status to ensure UI is correct after error
            fetch('/get_status')
                .then(res => res.json())
                .then(status => updateCombinedButtonStates(status));
        });
    });

    // Search bar input event
    searchBar.addEventListener('input', filterAndRenderMainPackets);
});

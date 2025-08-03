document.addEventListener("DOMContentLoaded", function () {
  const tableBody = document.querySelector("#log-table tbody");
  const columnInputs = document.querySelectorAll(".column-input");
  const sortableHeaders = document.querySelectorAll(".sortable-header");
  const fileSelect = document.getElementById("fileSelect");
  const fileUpload = document.getElementById("fileUpload");

  let logData = []; // Original data
  let filteredData = []; // Filtered data
  let currentSort = { column: null, direction: "asc" };
  let columnFilters = {};
  let messageDataStore = new Map(); // Store message data by unique key
  let timestampRange = { min: null, max: null };
  let timestampFilter = { start: null, end: null };
  let currentFile = null;

  // File handling functions
  function loadAvailableFiles() {
    fetch("/api/files")
      .then((response) => response.json())
      .then((data) => {
        if (data.files && data.files.length > 0) {
          // Clear existing options
          fileSelect.innerHTML = "";

          // Add files to dropdown
          data.files.forEach((file) => {
            const option = document.createElement("option");
            option.value = file.filename;
            option.textContent = file.display_name;
            fileSelect.appendChild(option);
          });

          // Select the first file (newest) by default
          currentFile = data.files[0].filename;
          fileSelect.value = currentFile;

          // Load logs for the selected file
          loadLogs(currentFile);
        } else {
          // No files available, show error
          tableBody.innerHTML = `<tr><td colspan="8" class="error-message">No log files available. Please upload a log file.</td></tr>`;
        }
      })
      .catch((error) => {
        console.error("Error loading files:", error);
        tableBody.innerHTML = `<tr><td colspan="8" class="error-message">Error loading files. Please try refreshing the page.</td></tr>`;
      });
  }

  function loadLogs(filename) {
    const url = filename
      ? `/api/logs?file=${encodeURIComponent(filename)}`
      : "/api/logs";

    fetch(url)
      .then((response) => response.json())
      .then((data) => {
        if (data.error) {
          tableBody.innerHTML = `<tr><td colspan="8" class="error-message">${data.error}</td></tr>`;
          return;
        }

        // Handle new response format
        logData = data.logs || data;
        filteredData = [...logData];

        // Set up timestamp range if available
        if (data.timestamp_range) {
          timestampRange = data.timestamp_range;
          initializeTimestampSlider();
        }

        renderTable(filteredData);

        // Load dashboard after logs are loaded
        loadDashboard(filename);
      })
      .catch((error) => {
        console.error("Error fetching log data:", error);
        tableBody.innerHTML = `<tr><td colspan="8" class="error-message">Error loading logs. Please try refreshing the page.</td></tr>`;
      });
  }

  function handleFileUpload() {
    const file = fileUpload.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);
    formData.append("logType", "modsecurity");

    // Show upload progress
    const uploadButton = document.querySelector(".upload-button");
    const originalText = uploadButton.textContent;
    uploadButton.innerHTML = "<span>Uploading...</span>";
    uploadButton.style.pointerEvents = "none";

    fetch("/api/upload", {
      method: "POST",
      body: formData,
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          // Refresh file list and select the new file
          loadAvailableFiles();
          // Show success message briefly
          uploadButton.innerHTML = "<span>✓ Uploaded</span>";
          setTimeout(() => {
            uploadButton.innerHTML = `<svg class="upload-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
          </svg>Upload File`;
            uploadButton.style.pointerEvents = "";
          }, 2000);
        } else {
          alert(data.error || "Upload failed");
          uploadButton.innerHTML = originalText;
          uploadButton.style.pointerEvents = "";
        }
      })
      .catch((error) => {
        console.error("Upload error:", error);
        alert("Upload failed: " + error.message);
        uploadButton.innerHTML = originalText;
        uploadButton.style.pointerEvents = "";
      });

    // Clear the input
    fileUpload.value = "";
  }

  // Event listeners for file controls
  fileSelect.addEventListener("change", (e) => {
    currentFile = e.target.value;
    loadLogs(currentFile);
  });

  fileUpload.addEventListener("change", handleFileUpload);

  // Initialize by loading available files
  loadAvailableFiles();

  function getStatusBadgeClass(status) {
    const statusCode = parseInt(status);
    if (statusCode >= 200 && statusCode < 300) return "status-2xx";
    if (statusCode >= 300 && statusCode < 400) return "status-3xx";
    if (statusCode >= 400 && statusCode < 500) return "status-4xx";
    if (statusCode >= 500) return "status-5xx";
    return "";
  }

  function showMessageModal(messageKey) {
    const modal = document.getElementById("messageModal");
    const modalBody = document.getElementById("messageModalBody");

    // Get messages from store
    const messages = messageDataStore.get(messageKey) || [];

    // Show full messages without any parsing or truncation
    const fullMessageContent = messages.join("\n\n");
    modalBody.textContent = fullMessageContent || "No messages available";

    modal.classList.add("active");
    document.body.style.overflow = "hidden"; // Prevent background scrolling
  }

  function closeMessageModal() {
    const modal = document.getElementById("messageModal");
    modal.classList.remove("active");
    document.body.style.overflow = ""; // Restore scrolling
  }

  // Close modal when clicking outside the content
  document
    .getElementById("messageModal")
    .addEventListener("click", function (e) {
      if (e.target === this) {
        closeMessageModal();
      }
    });

  // Close modal with Escape key
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      closeMessageModal();
    }
  });

  function renderTable(data) {
    if (data.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="8" class="loading">No logs found matching your filters.</td></tr>`;
      return;
    }

    tableBody.innerHTML = ""; // Clear existing data
    messageDataStore.clear(); // Clear message data store

    data.forEach((logEntry, index) => {
      const statusClass = getStatusBadgeClass(logEntry.response_status);
      const messagesPreview = logEntry.messages.slice(0, 3).join("<br>");
      const hasMoreMessages = logEntry.messages.length > 3;
      const truncatedMessages =
        messagesPreview + (hasMoreMessages ? "<br>..." : "");

      // Store raw messages in data store with unique key for modal display
      const messageKey = `msg_${logEntry.id}_${index}`;
      messageDataStore.set(
        messageKey,
        logEntry.raw_messages || logEntry.messages
      );

      const row = document.createElement("tr");
      row.innerHTML = `
        <td class="id-cell">${logEntry.id}</td>
                            <td class="timestamp-cell">${
                              logEntry.display_timestamp || logEntry.timestamp
                            }</td>
        <td class="ip-cell">${logEntry.source_ip}</td>
        <td class="port-cell">${logEntry.source_port}</td>
        <td class="dest-port-cell">${logEntry.destination_port}</td>
        <td class="request-cell" title="${logEntry.request_line}">${
        logEntry.request_line
      }</td>
        <td class="status-cell">
          <span class="status-badge ${statusClass}">${
        logEntry.response_status
      }</span>
        </td>
        <td class="messages-cell">
          <div class="messages-content">
            ${truncatedMessages}
            <div class="magnify-icon" onclick="showMessageModal('${messageKey}')" title="View full message">🔍</div>
          </div>
        </td>
      `;
      tableBody.appendChild(row);
    });
  }

  // Make modal functions globally accessible
  window.showMessageModal = showMessageModal;
  window.closeMessageModal = closeMessageModal;

  // Dashboard variables
  let ipChart = null;
  let statusChart = null;
  let selectedIP = null; // Track selected IP for filtering
  let statusChartFiltered = null; // Track which status code is filtered (show only)
  let statusChartHidden = new Set(); // Track which status codes are hidden

  // Dashboard functions
  function loadDashboard(filename = null) {
    const url = filename
      ? `/api/dashboard?file=${encodeURIComponent(filename)}`
      : "/api/dashboard";

    fetch(url)
      .then((response) => response.json())
      .then((data) => {
        if (data.error) {
          console.error("Dashboard error:", data.error);
          return;
        }
        renderIpChart(data.top_ips);
        renderStatusChart(data.status_timeline, data.status_codes);
      })
      .catch((error) => {
        console.error("Error loading dashboard:", error);
      });
  }

  // Helper function to get theme-aware chart colors
  function getChartTheme() {
    const isDark =
      document.documentElement.getAttribute("data-theme") === "dark";

    return {
      textColor: isDark ? "hsl(210, 40%, 98%)" : "hsl(222.2, 84%, 4.9%)",
      mutedTextColor: isDark
        ? "hsl(215, 20.2%, 65.1%)"
        : "hsl(215.4, 16.3%, 46.9%)",
      gridColor: isDark
        ? "hsl(217.2, 32.6%, 17.5%)"
        : "hsl(214.3, 31.8%, 91.4%)",
      borderColor: isDark
        ? "hsl(217.2, 32.6%, 17.5%)"
        : "hsl(214.3, 31.8%, 91.4%)",
      backgroundColor: isDark ? "hsl(222.2, 84%, 4.9%)" : "hsl(0, 0%, 100%)",
      tooltipBg: isDark ? "hsl(222.2, 84%, 4.9%)" : "hsl(0, 0%, 100%)",
      shadowColor: isDark ? "rgba(0, 0, 0, 0.3)" : "rgba(0, 0, 0, 0.1)",
    };
  }

  function renderIpChart(topIps) {
    const ctx = document.getElementById("ipChart").getContext("2d");
    const theme = getChartTheme();

    // Update chart title to show active filter
    const chartTitle = document.querySelector(".dashboard-card h3");
    if (chartTitle) {
      if (selectedIP) {
        chartTitle.textContent = `Top 10 Source IPs (Filtered: ${selectedIP})`;
        chartTitle.style.color = "hsl(0, 84.2%, 60.2%)"; // Theme-aware red
      } else {
        chartTitle.textContent = "Top 10 Source IPs";
        chartTitle.style.color = ""; // Reset to default
      }
    }

    const labels = Object.keys(topIps);
    const data = Object.values(topIps);

    // Colors matching Apache error logs severity distribution chart with complementary additions
    const baseColors = [
      "#ef4444", // Red (emergency/alert)
      "#f97316", // Orange (critical/error)
      "#eab308", // Yellow (warning)
      "#3b82f6", // Blue (notice/info)
      "#6b7280", // Gray (debug)
      "#dc2626", // Dark red (complementary to red)
      "#ea580c", // Dark orange (complementary to orange)
      "#ca8a04", // Dark yellow/amber (complementary to yellow)
      "#2563eb", // Dark blue (complementary to blue)
      "#4b5563", // Dark gray (complementary to gray)
      "#f87171", // Light red (complementary variant)
      "#fb923c", // Light orange (complementary variant)
      "#fbbf24", // Light yellow (complementary variant)
      "#60a5fa", // Light blue (complementary variant)
      "#9ca3af", // Light gray (complementary variant)
    ];

    const backgroundColors = labels.map((ip, index) => {
      const baseColor = baseColors[index % baseColors.length];
      if (selectedIP && selectedIP !== ip) {
        return baseColor + "4D"; // Add 30% opacity (4D in hex)
      } else if (selectedIP === ip) {
        return baseColor; // Full color for selected
      }
      return baseColor + "E6"; // Add 90% opacity (E6 in hex)
    });

    const borderColors = labels.map((ip, index) => {
      const baseColor = baseColors[index % baseColors.length];
      if (selectedIP === ip) {
        return theme.textColor; // Theme-aware border for selected
      }
      return baseColor;
    });

    if (!ipChart) {
      ipChart = new Chart(ctx, {
        type: "bar",
        data: {
          labels: labels,
          datasets: [
            {
              label: "Request Count",
              data: data,
              backgroundColor: backgroundColors,
              borderColor: borderColors,
              borderWidth: selectedIP ? 2 : 1,
              borderRadius: 0, // Flat bars instead of rounded
              borderSkipped: false,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          onClick: (event, elements) => {
            if (elements.length > 0) {
              const elementIndex = elements[0].index;
              const clickedIP = labels[elementIndex];
              handleIpSelection(clickedIP);
            }
          },
          onHover: (event, activeElements) => {
            event.native.target.style.cursor =
              activeElements.length > 0 ? "pointer" : "default";
          },
          plugins: {
            legend: {
              display: false,
            },
            title: {
              display: false, // Let the HTML handle the title to match Apache error logs style
            },
            tooltip: {
              backgroundColor: theme.tooltipBg,
              titleColor: theme.textColor,
              bodyColor: theme.textColor,
              borderColor: theme.borderColor,
              borderWidth: 1,
              cornerRadius: 8,
              padding: 12,
              titleFont: {
                family:
                  '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
                size: 13,
                weight: "500",
              },
              bodyFont: {
                family:
                  '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
                size: 12,
              },
              boxShadow: `0 4px 6px -1px ${theme.shadowColor}`,
              callbacks: {
                afterLabel: function (context) {
                  return selectedIP === context.label
                    ? "(Click to remove filter)"
                    : "(Click to filter)";
                },
              },
            },
          },
          scales: {
            y: {
              beginAtZero: true,
              border: {
                display: false,
              },
              grid: {
                color: theme.gridColor,
                lineWidth: 1,
              },
              ticks: {
                stepSize: 1,
                color: theme.mutedTextColor,
                font: {
                  family:
                    '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
                  size: 11,
                },
                padding: 8,
              },
            },
            x: {
              border: {
                display: false,
              },
              grid: {
                display: false,
              },
              ticks: {
                color: theme.mutedTextColor,
                font: {
                  family:
                    '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
                  size: 11,
                },
                maxRotation: 45,
                padding: 8,
              },
            },
          },
        },
      });
    } else {
      // Update existing chart data
      ipChart.data.labels = labels;
      ipChart.data.datasets[0].data = data;
      ipChart.data.datasets[0].backgroundColor = backgroundColors;
      ipChart.data.datasets[0].borderColor = borderColors;
      ipChart.data.datasets[0].borderWidth = selectedIP ? 2 : 1;
    }

    // Update chart with animations
    ipChart.update();
  }

  function renderStatusChart(timeline, statusCodes) {
    const ctx = document.getElementById("statusChart").getContext("2d");
    const theme = getChartTheme();

    // Update existing chart if it exists

    if (timeline.length === 0) {
      return;
    }

    const labels = timeline.map((item) => item.time);

    // Highly differentiated shadcn color palette for HTTP status codes
    const statusColorMap = {
      // 1xx Informational - Distinct blue spectrum
      100: "hsl(221.2, 83.2%, 53.3%)", // Blue-500
      101: "hsl(239.2, 85.2%, 64.9%)", // Indigo-400
      102: "hsl(262.1, 83.3%, 57.8%)", // Violet-500

      // 2xx Success - Varied green spectrum
      200: "hsl(142.1, 76.2%, 36.3%)", // Green-600
      201: "hsl(125.4, 63.2%, 41.8%)", // Emerald-600
      202: "hsl(83.8, 69.4%, 51.8%)", // Lime-500
      204: "hsl(152.2, 69%, 31%)", // Emerald-800
      206: "hsl(84.8, 85.2%, 40.4%)", // Lime-600

      // 3xx Redirection - Diverse cool colors
      300: "hsl(188.7, 94.5%, 42.7%)", // Cyan-600
      301: "hsl(173.4, 80.4%, 40%)", // Teal-600
      302: "hsl(198.6, 88.7%, 48.4%)", // Sky-500
      303: "hsl(204.4, 98%, 47.8%)", // Sky-600
      304: "hsl(210.4, 98%, 43.9%)", // Blue-700
      307: "hsl(217.2, 91.2%, 59.8%)", // Blue-500
      308: "hsl(170.6, 76.9%, 42.3%)", // Teal-500

      // 4xx Client Errors - Highly contrasted warm colors
      400: "hsl(24.6, 95%, 53.1%)", // Orange-500
      401: "hsl(0, 84.2%, 60.2%)", // Red-500
      403: "hsl(330.4, 81.2%, 60.4%)", // Pink-400
      404: "hsl(292.2, 84.1%, 60.6%)", // Pink-500
      405: "hsl(280.4, 89.5%, 68.6%)", // Fuchsia-400
      406: "hsl(270.7, 91%, 65.1%)", // Purple-400
      408: "hsl(32.1, 94.6%, 43.7%)", // Amber-600
      409: "hsl(43.3, 96.4%, 56.3%)", // Yellow-400
      410: "hsl(16.2, 82.5%, 43.9%)", // Orange-700
      413: "hsl(354.3, 70.2%, 47.1%)", // Rose-600
      429: "hsl(12.0, 76.9%, 40.2%)", // Orange-800

      // 5xx Server Errors - Full spectrum of intense colors
      500: "hsl(0, 84.2%, 60.2%)", // Red-500
      501: "hsl(346.8, 77.2%, 49.8%)", // Rose-500
      502: "hsl(349.7, 89.2%, 60.2%)", // Rose-400
      503: "hsl(0, 62.8%, 30.6%)", // Red-800
      504: "hsl(0, 72.2%, 50.6%)", // Red-600
      505: "hsl(322.2, 78.8%, 38.7%)", // Fuchsia-700
      507: "hsl(314.4, 84%, 52.9%)", // Fuchsia-500
      508: "hsl(300.4, 67.2%, 44.5%)", // Purple-600
      509: "hsl(258.3, 89.5%, 66.3%)", // Violet-400
      510: "hsl(248.7, 83.8%, 57.8%)", // Indigo-500
    };

    // Highly contrasted fallback colors across full spectrum
    const fallbackColors = [
      "hsl(47.9, 95.8%, 53.1%)", // Yellow-500
      "hsl(158.1, 64.4%, 51.6%)", // Teal-500
      "hsl(271.5, 81.3%, 55.9%)", // Purple-500
      "hsl(142.1, 76.2%, 36.3%)", // Green-600
      "hsl(340.6, 82.2%, 52.5%)", // Pink-600
      "hsl(217.2, 91.2%, 59.8%)", // Blue-500
      "hsl(31.8, 81%, 28.8%)", // Orange-900
      "hsl(160.1, 84.1%, 39.4%)", // Emerald-700
      "hsl(293.4, 69.5%, 48.8%)", // Fuchsia-600
      "hsl(200.4, 98%, 39.4%)", // Sky-700
      "hsl(115.7, 60.4%, 30.9%)", // Green-800
      "hsl(335.4, 75.6%, 36.3%)", // Rose-700
      "hsl(263.4, 70%, 50.4%)", // Violet-600
      "hsl(39.3, 85.2%, 47.1%)", // Amber-500
      "hsl(186.2, 100%, 26.9%)", // Cyan-900
      "hsl(312.9, 73.0%, 30.6%)", // Fuchsia-800
      "hsl(234.7, 89.5%, 73.7%)", // Indigo-300
      "hsl(27.8, 87.5%, 67.1%)", // Orange-300
      "hsl(149.3, 80.4%, 28.0%)", // Emerald-900
      "hsl(280.7, 60.8%, 41.8%)", // Purple-700
    ];

    const datasets = statusCodes.map((status, index) => {
      const color =
        statusColorMap[status] || fallbackColors[index % fallbackColors.length];
      return {
        label: `HTTP ${status}`,
        data: timeline.map((item) => item[status] || 0),
        borderColor: color,
        backgroundColor: color.replace(")", ", 0.1)").replace("hsl(", "hsla("),
        pointBackgroundColor: color,
        pointBorderColor: color,
        pointHoverBackgroundColor: color,
        pointHoverBorderColor: theme.backgroundColor,
        tension: 0.3,
        fill: false,
        borderWidth: 2.5,
        pointRadius: 5,
        pointHoverRadius: 7,
        pointBorderWidth: 2,
        pointHoverBorderWidth: 3,
      };
    });

    if (!statusChart) {
      statusChart = new Chart(ctx, {
        type: "line",
        data: {
          labels: labels,
          datasets: datasets,
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {
            intersect: false,
            mode: "index",
          },
          plugins: {
            legend: {
              position: "top",
              align: "start",
              labels: {
                color: theme.textColor,
                usePointStyle: true,
                pointStyle: "circle",
                padding: 16,
                boxWidth: 8,
                boxHeight: 8,
                font: {
                  family:
                    '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
                  size: 11,
                  weight: "500",
                },
              },
              onClick: (e, legendItem, legend) => {
                // Custom legend click handler
                showLegendContextMenu(e, legendItem, legend);
              },
            },
            tooltip: {
              backgroundColor: theme.tooltipBg,
              titleColor: theme.textColor,
              bodyColor: theme.textColor,
              borderColor: theme.borderColor,
              borderWidth: 1,
              cornerRadius: 8,
              padding: 12,
              usePointStyle: true,
              titleFont: {
                family:
                  '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
                size: 13,
                weight: "500",
              },
              bodyFont: {
                family:
                  '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
                size: 12,
              },
              boxShadow: `0 4px 6px -1px ${theme.shadowColor}`,
            },
          },
          scales: {
            y: {
              beginAtZero: true,
              border: {
                display: false,
              },
              grid: {
                color: theme.gridColor,
                lineWidth: 1,
              },
              ticks: {
                stepSize: 1,
                color: theme.mutedTextColor,
                font: {
                  family:
                    '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
                  size: 11,
                },
                padding: 8,
              },
            },
            x: {
              border: {
                display: false,
              },
              grid: {
                color: theme.gridColor,
                lineWidth: 1,
              },
              ticks: {
                color: theme.mutedTextColor,
                font: {
                  family:
                    '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
                  size: 11,
                },
                maxRotation: 45,
                padding: 8,
              },
            },
          },
        },
      });
    } else {
      // Update existing chart data
      statusChart.data.labels = labels;
      statusChart.data.datasets = datasets;
    }

    // Apply saved filter and hidden states
    statusChart.data.datasets.forEach((dataset, index) => {
      const statusCode = dataset.label.replace("HTTP ", "");
      const meta = statusChart.getDatasetMeta(index);

      // Apply hidden state
      if (statusChartHidden.has(statusCode)) {
        meta.hidden = true;
      }
      // Apply filter state (only show filtered status, hide others)
      else if (statusChartFiltered && statusChartFiltered !== statusCode) {
        meta.hidden = true;
      }
      // Show if not hidden and not filtered out
      else {
        meta.hidden = false;
      }
    });

    statusChart.update(); // Update with full animations
  }

  // Legend context menu functions
  function showLegendContextMenu(event, legendItem, legend) {
    const contextMenu = document.getElementById("legendContextMenu");
    const showAllOption = document.getElementById("contextShowAllOption");
    const filterOption = document.getElementById("contextFilterOption");
    const hideOption = document.getElementById("contextHideOption");
    const showOption = document.getElementById("contextShowOption");

    // Get the status code from legend label (e.g., "HTTP 404" -> "404")
    const statusCode = legendItem.text.replace("HTTP ", "");

    // Position the context menu near the mouse cursor
    const rect = legend.chart.canvas.getBoundingClientRect();

    // Use the native event if available, otherwise use Chart.js event coordinates
    let mouseX, mouseY;
    if (event.native) {
      mouseX = event.native.offsetX || event.x;
      mouseY = event.native.offsetY || event.y;
    } else {
      mouseX = event.x || 0;
      mouseY = event.y || 0;
    }

    contextMenu.style.left = rect.left + mouseX + 10 + "px";
    contextMenu.style.top = rect.top + mouseY + 10 + "px";
    contextMenu.style.display = "block";

    // Determine current state
    const totalDatasets = statusChart.data.datasets.length;
    const hiddenCount = statusChartHidden.size;
    const hasFilter = statusChartFiltered !== null;

    // Calculate actual visible count (considering both hidden and filter)
    const actualVisibleCount = hasFilter ? 1 : totalDatasets - hiddenCount;

    // A status code is actually visible if:
    // 1. It's not in the hidden set AND
    // 2. Either there's no filter OR it's the filtered status code
    const isCurrentStatusActuallyVisible =
      !statusChartHidden.has(statusCode) &&
      (!hasFilter || statusChartFiltered === statusCode);

    // Hide all options initially
    showAllOption.style.display = "none";
    filterOption.style.display = "none";
    hideOption.style.display = "none";
    showOption.style.display = "none";

    // Scenario 1: All status codes are visible
    if (hiddenCount === 0 && !hasFilter) {
      // Any status code: 'Hide', 'Show Only This'
      hideOption.style.display = "block";
      filterOption.style.display = "block";
    }
    // Scenario 2: One status code visible, all others hidden
    else if (actualVisibleCount === 1) {
      if (!isCurrentStatusActuallyVisible) {
        // Hidden status code: 'Show All', 'Show Only This', 'Show'
        showAllOption.style.display = "block";
        filterOption.style.display = "block";
        showOption.style.display = "block";
      } else {
        // The one visible status code: 'Show All' (only)
        showAllOption.style.display = "block";
      }
    }
    // Scenario 3: Multiple visible and multiple hidden
    else {
      if (!isCurrentStatusActuallyVisible) {
        // Hidden status code: 'Show All', 'Show Only This', 'Show'
        showAllOption.style.display = "block";
        filterOption.style.display = "block";
        showOption.style.display = "block";
      } else {
        // Visible status code: 'Show All', 'Show Only This', 'Hide'
        showAllOption.style.display = "block";
        filterOption.style.display = "block";
        hideOption.style.display = "block";
      }
    }

    // Store the current legend item for use in click handlers
    contextMenu.dataset.statusCode = statusCode;
    contextMenu.dataset.datasetIndex = legendItem.datasetIndex;
  }

  function hideLegendContextMenu() {
    const contextMenu = document.getElementById("legendContextMenu");
    contextMenu.style.display = "none";
  }

  function handleShowAll() {
    // Show all datasets and clear all filters/hidden states
    statusChartFiltered = null;
    statusChartHidden.clear();
    statusChart.data.datasets.forEach((dataset, index) => {
      const meta = statusChart.getDatasetMeta(index);
      meta.hidden = false;
    });

    statusChart.update();
    hideLegendContextMenu();
  }

  function handleLegendFilter(statusCode, datasetIndex) {
    // Show only this status code (hide all others)
    statusChartFiltered = statusCode;
    statusChartHidden.clear(); // Clear hidden states since we're filtering
    statusChart.data.datasets.forEach((dataset, index) => {
      const meta = statusChart.getDatasetMeta(index);
      const datasetStatusCode = dataset.label.replace("HTTP ", "");
      meta.hidden = datasetStatusCode !== statusCode;
    });

    statusChart.update();
    hideLegendContextMenu();
  }

  function handleLegendHide(statusCode, datasetIndex) {
    // Hide only this specific status code
    statusChartHidden.add(statusCode);
    const meta = statusChart.getDatasetMeta(datasetIndex);
    meta.hidden = true;

    // If this was the filtered status, clear the filter
    if (statusChartFiltered === statusCode) {
      statusChartFiltered = null;
    }

    statusChart.update();
    hideLegendContextMenu();
  }

  function handleLegendShow(statusCode, datasetIndex) {
    // Show this specific status code (remove from hidden set)
    statusChartHidden.delete(statusCode);
    const meta = statusChart.getDatasetMeta(datasetIndex);

    // Always make this legend visible when "Show" is clicked
    meta.hidden = false;

    statusChart.update();
    hideLegendContextMenu();
  }

  function handleIpSelection(clickedIP) {
    // Toggle IP selection
    if (selectedIP === clickedIP) {
      // Deselect if clicking the same IP
      selectedIP = null;
      // Clear the source IP filter input
      const sourceIpInput = document.querySelector('[data-column="source_ip"]');
      if (sourceIpInput) {
        sourceIpInput.value = "";
      }
      // Remove from columnFilters
      delete columnFilters["source_ip"];
    } else {
      // Select new IP
      selectedIP = clickedIP;
      // Set the source IP filter input
      const sourceIpInput = document.querySelector('[data-column="source_ip"]');
      if (sourceIpInput) {
        sourceIpInput.value = clickedIP;
      }
      // Add to columnFilters
      columnFilters["source_ip"] = clickedIP;
    }

    // Refresh the chart to show selection state
    loadDashboard(currentFile);

    // Apply filters to table
    applyFilters();
  }

  // Timestamp slider functions
  function initializeTimestampSlider() {
    if (!timestampRange.min || !timestampRange.max) {
      return;
    }

    // Show the entire filter section
    const filterSection = document.getElementById("filterSection");
    filterSection.style.display = "block";

    // Show the slider container and values
    const sliderContainer = document.getElementById("timestampSliderContainer");
    const sliderValues = document.getElementById("sliderValues");
    sliderContainer.style.display = "block";
    sliderValues.style.display = "flex";

    // Set up initial values
    document.getElementById("startValue").textContent = timestampRange.min;
    document.getElementById("endValue").textContent = timestampRange.max;

    // Initialize filter range to full range
    timestampFilter.start = timestampRange.min;
    timestampFilter.end = timestampRange.max;

    // Set up slider event listeners
    const startRange = document.getElementById("startRange");
    const endRange = document.getElementById("endRange");
    const resetButton = document.getElementById("resetTimeFilter");

    startRange.addEventListener("input", updateSlider);
    endRange.addEventListener("input", updateSlider);
    resetButton.addEventListener("click", resetTimestampFilter);

    // Initialize slider visual
    updateSliderRange();

    // Initialize reset button state
    updateResetButton();
  }

  function updateSlider() {
    const startRange = document.getElementById("startRange");
    const endRange = document.getElementById("endRange");

    let startValue = parseInt(startRange.value);
    let endValue = parseInt(endRange.value);

    // Ensure start is always less than end
    if (startValue >= endValue) {
      if (startRange === document.activeElement) {
        endValue = startValue + 1;
        endRange.value = endValue;
      } else {
        startValue = endValue - 1;
        startRange.value = startValue;
      }
    }

    // Convert slider values to timestamps
    const timestamps = logData
      .map((log) => log.display_timestamp || log.timestamp)
      .filter((ts) => ts !== "N/A")
      .sort();

    if (timestamps.length === 0) return;

    const startIndex = Math.floor((startValue / 100) * (timestamps.length - 1));
    const endIndex = Math.floor((endValue / 100) * (timestamps.length - 1));

    timestampFilter.start = timestamps[startIndex];
    timestampFilter.end = timestamps[endIndex];

    // Update display values
    document.getElementById("startValue").textContent = timestampFilter.start;
    document.getElementById("endValue").textContent = timestampFilter.end;

    // Update visual range
    updateSliderRange();

    // Apply filters
    applyFilters();

    // Show/hide reset button
    updateResetButton();
  }

  function updateSliderRange() {
    const startRange = document.getElementById("startRange");
    const endRange = document.getElementById("endRange");
    const sliderRange = document.getElementById("sliderRange");

    const startPercent = (startRange.value / startRange.max) * 100;
    const endPercent = (endRange.value / endRange.max) * 100;

    sliderRange.style.left = startPercent + "%";
    sliderRange.style.width = endPercent - startPercent + "%";
  }

  function isTimestampInRange(timestamp) {
    if (!timestampFilter.start || !timestampFilter.end) {
      return true;
    }

    // Simple string comparison should work for our format "29 Jun 21:44"
    return (
      timestamp >= timestampFilter.start && timestamp <= timestampFilter.end
    );
  }

  function updateResetButton() {
    const resetBtn = document.getElementById("resetTimeFilter");
    const isFiltered =
      timestampFilter.start !== timestampRange.min ||
      timestampFilter.end !== timestampRange.max;

    if (isFiltered) {
      resetBtn.style.display = "inline-block";
      resetBtn.style.backgroundColor = "hsl(var(--muted) / 0.1)";
      resetBtn.style.color = "hsl(var(--foreground))";
    } else {
      resetBtn.style.display = "none";
    }
  }

  function resetTimestampFilter() {
    if (!timestampRange.min || !timestampRange.max) return;

    // Reset slider values
    document.getElementById("startRange").value = 0;
    document.getElementById("endRange").value = 100;

    // Reset filter range
    timestampFilter.start = timestampRange.min;
    timestampFilter.end = timestampRange.max;

    // Update display
    document.getElementById("startValue").textContent = timestampRange.min;
    document.getElementById("endValue").textContent = timestampRange.max;

    // Update visual range
    updateSliderRange();

    // Apply filters and update button
    applyFilters();
    updateResetButton();
  }

  function applyFilters() {
    filteredData = logData.filter((entry) => {
      // Check timestamp range filter first
      if (!isTimestampInRange(entry.display_timestamp || entry.timestamp)) {
        return false;
      }

      // Then check column filters
      return Object.entries(columnFilters).every(([column, filterValue]) => {
        if (!filterValue) return true;

        let cellValue = "";
        if (column === "messages") {
          cellValue = entry[column].join(" ").toLowerCase();
        } else if (column === "source_port" || column === "destination_port") {
          cellValue = entry[column].toString();
        } else {
          cellValue = (entry[column] || "").toString().toLowerCase();
        }

        return cellValue.includes(filterValue.toLowerCase());
      });
    });

    // Apply current sort
    if (currentSort.column) {
      applySorting(currentSort.column, currentSort.direction, false);
    }

    renderTable(filteredData);
  }

  function applySorting(column, direction, updateData = true) {
    currentSort = { column, direction };

    filteredData.sort((a, b) => {
      let aVal, bVal;

      if (column === "messages") {
        aVal = a[column].join(" ");
        bVal = b[column].join(" ");
      } else if (column === "response_status") {
        aVal = parseInt(a[column]) || 0;
        bVal = parseInt(b[column]) || 0;
      } else if (column === "source_port" || column === "destination_port") {
        aVal = parseInt(a[column]) || 0;
        bVal = parseInt(b[column]) || 0;
      } else {
        aVal = (a[column] || "").toString().toLowerCase();
        bVal = (b[column] || "").toString().toLowerCase();
      }

      if (typeof aVal === "number" && typeof bVal === "number") {
        return direction === "asc" ? aVal - bVal : bVal - aVal;
      }

      if (aVal < bVal) return direction === "asc" ? -1 : 1;
      if (aVal > bVal) return direction === "asc" ? 1 : -1;
      return 0;
    });

    // Update sort icons
    document.querySelectorAll(".sort-icon").forEach((icon) => {
      icon.textContent = "↕";
      icon.classList.remove("active");
    });

    const activeIcon = document.querySelector(
      `[data-column="${column}"] .sort-icon`
    );
    if (activeIcon) {
      activeIcon.textContent = direction === "asc" ? "▲" : "▼";
      activeIcon.classList.add("active");
    }

    if (updateData) {
      renderTable(filteredData);
    }
  }

  // Column filter event listeners
  columnInputs.forEach((input) => {
    input.addEventListener("input", (e) => {
      const column = e.target.dataset.column;
      const value = e.target.value.trim();

      if (value === "") {
        delete columnFilters[column];
        // Clear IP selection if source_ip filter is cleared manually
        if (column === "source_ip") {
          selectedIP = null;
          loadDashboard(currentFile); // Refresh chart to remove selection highlight
        }
      } else {
        columnFilters[column] = value;
        // Update IP selection if source_ip filter is set manually
        if (column === "source_ip") {
          selectedIP = value;
          loadDashboard(currentFile); // Refresh chart to show selection highlight
        }
      }

      applyFilters();
    });
  });

  // Sort header event listeners
  sortableHeaders.forEach((header) => {
    header.addEventListener("click", (e) => {
      const column = e.currentTarget.dataset.column;
      let direction = "asc";

      if (currentSort.column === column && currentSort.direction === "asc") {
        direction = "desc";
      }

      applySorting(column, direction);
    });
  });

  // Legend context menu event listeners
  const contextShowAllOption = document.getElementById("contextShowAllOption");
  const contextFilterOption = document.getElementById("contextFilterOption");
  const contextHideOption = document.getElementById("contextHideOption");
  const contextShowOption = document.getElementById("contextShowOption");
  const legendContextMenu = document.getElementById("legendContextMenu");

  contextShowAllOption.addEventListener("click", () => {
    handleShowAll();
  });

  contextFilterOption.addEventListener("click", () => {
    const statusCode = legendContextMenu.dataset.statusCode;
    const datasetIndex = parseInt(legendContextMenu.dataset.datasetIndex);
    handleLegendFilter(statusCode, datasetIndex);
  });

  contextHideOption.addEventListener("click", () => {
    const statusCode = legendContextMenu.dataset.statusCode;
    const datasetIndex = parseInt(legendContextMenu.dataset.datasetIndex);
    handleLegendHide(statusCode, datasetIndex);
  });

  contextShowOption.addEventListener("click", () => {
    const statusCode = legendContextMenu.dataset.statusCode;
    const datasetIndex = parseInt(legendContextMenu.dataset.datasetIndex);
    handleLegendShow(statusCode, datasetIndex);
  });

  // Close context menu when clicking outside
  document.addEventListener("click", (e) => {
    if (!legendContextMenu.contains(e.target)) {
      hideLegendContextMenu();
    }
  });

  // Theme toggle functionality
  function initializeThemeToggle() {
    const themeToggle = document.getElementById("themeToggle");
    const themeText = themeToggle.querySelector(".theme-text");

    // Check for saved theme preference or default to light mode
    const savedTheme = localStorage.getItem("theme") || "light";
    setTheme(savedTheme);

    // Theme toggle event listener
    themeToggle.addEventListener("click", () => {
      const currentTheme =
        document.documentElement.getAttribute("data-theme") || "light";
      const newTheme = currentTheme === "light" ? "dark" : "light";
      setTheme(newTheme);
    });

    function setTheme(theme) {
      document.documentElement.setAttribute("data-theme", theme);
      localStorage.setItem("theme", theme);

      // Update button text and tooltip
      if (theme === "dark") {
        themeText.textContent = "Dark Mode";
        themeToggle.setAttribute("data-tooltip", "Switch to Light Mode");
      } else {
        themeText.textContent = "Light Mode";
        themeToggle.setAttribute("data-tooltip", "Switch to Dark Mode");
      }

      // Re-render charts to apply new theme (only if charts have been created)
      if (currentFile && (ipChart || statusChart)) {
        loadDashboard(currentFile);
      }
    }
  }

  // Sidebar functionality
  function initializeSidebar() {
    const sidebar = document.getElementById("sidebar");
    const sidebarToggle = document.getElementById("sidebarToggle");
    const mainContent = document.querySelector(".main-content");

    if (!sidebar) return;

    // Load saved sidebar state (only on desktop)
    function loadSidebarState() {
      if (window.innerWidth >= 993) {
        const isCollapsed = localStorage.getItem("sidebarCollapsed") === "true";
        if (isCollapsed) {
          sidebar.classList.add("collapsed");
        }
      }
    }

    // Save sidebar state
    function saveSidebarState() {
      const isCollapsed = sidebar.classList.contains("collapsed");
      localStorage.setItem("sidebarCollapsed", isCollapsed);
    }

    // Toggle sidebar collapse (desktop only)
    function toggleSidebar() {
      if (window.innerWidth >= 993) {
        sidebar.classList.toggle("collapsed");
        saveSidebarState();
      }
    }

    // Auto-hide sidebar on smaller screens
    function handleResponsiveSidebar() {
      if (window.innerWidth < 993) {
        // On smaller screens, remove collapsed state and let mobile menu handle it
        sidebar.classList.remove("collapsed");
        if (window.closeMobileMenu) {
          window.closeMobileMenu();
        }
      } else {
        // On desktop, restore saved state
        loadSidebarState();
      }
    }

    // Event listeners
    if (sidebarToggle) {
      sidebarToggle.addEventListener("click", toggleSidebar);
    }

    // Handle window resize
    window.addEventListener("resize", handleResponsiveSidebar);

    // Initialize on load
    loadSidebarState();
  }

  // Mobile menu functionality
  function initializeMobileMenu() {
    const mobileMenuButton = document.getElementById("mobileMenuButton");
    const sidebar = document.getElementById("sidebar");
    const sidebarOverlay = document.getElementById("sidebarOverlay");

    if (!mobileMenuButton || !sidebar || !sidebarOverlay) {
      return; // Elements not found
    }

    // Toggle mobile menu
    function toggleMobileMenu() {
      const isOpen = sidebar.classList.contains("mobile-open");

      if (isOpen) {
        sidebar.classList.remove("mobile-open");
        sidebarOverlay.classList.remove("active");
        document.body.style.overflow = "";
      } else {
        sidebar.classList.add("mobile-open");
        sidebarOverlay.classList.add("active");
        document.body.style.overflow = "hidden"; // Prevent background scrolling
      }
    }

    // Close mobile menu
    window.closeMobileMenu = function () {
      sidebar.classList.remove("mobile-open");
      sidebarOverlay.classList.remove("active");
      document.body.style.overflow = "";
    };

    // Event listeners
    mobileMenuButton.addEventListener("click", toggleMobileMenu);
    sidebarOverlay.addEventListener("click", window.closeMobileMenu);

    // Close menu on escape key
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && sidebar.classList.contains("mobile-open")) {
        window.closeMobileMenu();
      }
    });

    // Close menu when screen becomes large enough
    window.addEventListener("resize", () => {
      if (window.innerWidth >= 992) {
        window.closeMobileMenu();
      }
    });
  }

  // Initialize theme first to ensure CSS custom properties are set correctly
  initializeThemeToggle();

  // Initialize sidebar functionality
  initializeSidebar();

  // Initialize mobile menu functionality
  initializeMobileMenu();

  // Force a layout recalculation to ensure responsive CSS is applied correctly
  document.body.offsetHeight;
});

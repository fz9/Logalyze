document.addEventListener("DOMContentLoaded", function () {
  // Apache Error Log viewer initialization

  // Global variables
  let currentLogs = [];
  let currentDashboardData = {};
  let charts = {};
  let selectedSeverity = null; // Track which severity level is filtered
  let logData = []; // Original data
  let filteredData = []; // Filtered data
  let timestampRange = { min: null, max: null };
  let timestampFilter = { start: null, end: null };
  let currentSort = { column: null, direction: "asc" };

  // DOM elements
  const tableBody = document.querySelector("#log-table tbody");
  const fileSelect = document.getElementById("fileSelect");
  const fileUpload = document.getElementById("fileUpload");
  const sortableHeaders = document.querySelectorAll(".sortable-header");

  // Initialize theme toggle (reuse from main app)
  initializeThemeToggle();

  // Initialize sidebar functionality
  initializeSidebar();

  // Initialize mobile menu
  initializeMobileMenu();

  // Initialize dashboard charts
  initializeCharts();

  // File handling functions
  function loadApacheErrorFiles() {
    fetch("/api/apache-error/files")
      .then((response) => response.json())
      .then((data) => {
        if (data.files && data.files.length > 0) {
          // Clear existing options
          fileSelect.innerHTML =
            '<option value="">Select Apache Error Log...</option>';

          // Add files to dropdown
          data.files.forEach((file) => {
            const option = document.createElement("option");
            option.value = file.filename;
            option.textContent = file.display_name || file.filename;
            fileSelect.appendChild(option);
          });

          // Select the first file (newest) by default and load it
          const currentFile = data.files[0].filename;
          fileSelect.value = currentFile;
          loadApacheErrorData(currentFile);
        } else {
          // No files available, show message
          showEmptyState();
        }
      })
      .catch((error) => {
        console.error("Error loading Apache error files:", error);
        showErrorState("Error loading files. Please try refreshing the page.");
      });
  }

  function showEmptyState() {
    if (tableBody) {
      tableBody.innerHTML =
        '<tr><td colspan="8" class="loading">Upload an Apache error log file to get started...</td></tr>';
    }
    if (fileSelect) {
      fileSelect.innerHTML =
        '<option value="">No Apache error log files available</option>';
    }
    // Clear charts
    clearCharts();
  }

  function showErrorState(message) {
    if (tableBody) {
      tableBody.innerHTML = `<tr><td colspan="8" class="error-message">${message}</td></tr>`;
    }
  }

  function loadApacheErrorData(filename) {
    if (!filename) return;

    // Clear any existing filters when loading new data
    selectedSeverity = null;
    timestampRange = { min: null, max: null };
    timestampFilter = { start: null, end: null };
    const severityInput = document.querySelector('[data-column="severity"]');
    if (severityInput) {
      severityInput.value = "";
    }

    // Hide filter section initially
    const filterSection = document.getElementById("filterSection");
    if (filterSection) {
      filterSection.style.display = "none";
    }

    // Load both logs and dashboard data in parallel
    Promise.all([
      loadApacheErrorLogs(filename),
      loadApacheErrorDashboard(filename),
    ]).catch((error) => {
      console.error("Error loading Apache error data:", error);
    });
  }

  function loadApacheErrorLogs(filename) {
    if (!filename) return Promise.resolve();

    const url = `/api/apache-error/logs?file=${encodeURIComponent(
      filename
    )}&limit=200`;

    return fetch(url)
      .then((response) => response.json())
      .then((data) => {
        if (data.error) {
          showErrorState(data.error);
          return;
        }

        // Store logs data globally
        currentLogs = data.logs || [];
        logData = [...currentLogs]; // Copy for filtering
        filteredData = [...logData]; // Copy for filtering
        timestampRange = data.timestamp_range || { min: null, max: null };

        // Initialize timestamp slider if we have time range data
        if (timestampRange.min && timestampRange.max) {
          initializeTimestampSlider();
        }

        // Render table
        renderApacheErrorTable(filteredData, data);

        // Update record counts
        updateRecordCounts();
      })
      .catch((error) => {
        console.error("Error fetching Apache error log data:", error);
        showErrorState("Error loading logs. Please try refreshing the page.");
      });
  }

  function loadApacheErrorDashboard(filename) {
    if (!filename) return Promise.resolve();

    const url = `/api/apache-error/dashboard?file=${encodeURIComponent(
      filename
    )}`;

    return fetch(url)
      .then((response) => response.json())
      .then((data) => {
        if (data.error) {
          console.error("Apache error dashboard error:", data.error);
          return;
        }

        // Store dashboard data globally
        currentDashboardData = data;

        // Update charts
        updateCharts(data);
      })
      .catch((error) => {
        console.error("Error loading Apache error dashboard:", error);
      });
  }

  function renderApacheErrorTable(logs, metadata) {
    if (!tableBody) return;

    if (!logs || logs.length === 0) {
      const emptyRow = document.createElement("tr");
      const emptyCell = document.createElement("td");
      emptyCell.setAttribute("colspan", "8");
      emptyCell.className = "loading";
      emptyCell.textContent = "No error log entries found.";
      emptyRow.appendChild(emptyCell);
      tableBody.innerHTML = ""; // Clear existing data
      tableBody.appendChild(emptyRow);
      return;
    }

    tableBody.innerHTML = ""; // Clear existing data

    logs.forEach((log, logIndex) => {
      const timestamp = formatTimestamp(log.timestamp);
      const severity = log.severity || "unknown";
      const module = log.module || "unknown";
      const pid = log.pid || "-";
      const clientIp = log.client_ip || "-";
      const clientPort = log.client_port || "-";
      const errorCode = log.error_code || "-";
      const message = log.message || "";
      const truncatedMessage =
        message.substring(0, 100) + (message.length > 100 ? "..." : "");

      const row = document.createElement("tr");

      // Create timestamp cell
      const timestampCell = document.createElement("td");
      timestampCell.className = "timestamp";
      timestampCell.textContent = timestamp;

      // Create severity cell
      const severityCell = document.createElement("td");
      severityCell.className = "severity";
      const severityBadge = document.createElement("span");
      severityBadge.className = `severity-badge severity-${severity.toLowerCase()}`;
      severityBadge.textContent = severity;
      severityCell.appendChild(severityBadge);

      // Create module cell
      const moduleCell = document.createElement("td");
      moduleCell.className = "module";
      moduleCell.textContent = module;

      // Create PID cell
      const pidCell = document.createElement("td");
      pidCell.className = "pid";
      pidCell.textContent = pid;

      // Create client IP cell
      const clientIpCell = document.createElement("td");
      clientIpCell.className = "client-ip";
      clientIpCell.textContent = clientIp;

      // Create client port cell
      const clientPortCell = document.createElement("td");
      clientPortCell.className = "client-port";
      clientPortCell.textContent = clientPort;

      // Create error code cell
      const errorCodeCell = document.createElement("td");
      errorCodeCell.className = "error-code";
      errorCodeCell.textContent = errorCode;

      // Create message cell
      const messageCell = document.createElement("td");
      messageCell.className = "message";
      const messagesContent = document.createElement("div");
      messagesContent.className = "messages-content";

      const messageText = document.createElement("span");
      messageText.textContent = truncatedMessage;
      messagesContent.appendChild(messageText);

      const magnifyIcon = document.createElement("div");
      magnifyIcon.className = "magnify-icon";
      magnifyIcon.textContent = "🔍";
      magnifyIcon.title = "View full details";
      magnifyIcon.addEventListener("click", () => showLogDetails(logIndex));
      messagesContent.appendChild(magnifyIcon);

      messageCell.appendChild(messagesContent);

      // Append all cells to row
      row.appendChild(timestampCell);
      row.appendChild(severityCell);
      row.appendChild(moduleCell);
      row.appendChild(pidCell);
      row.appendChild(clientIpCell);
      row.appendChild(clientPortCell);
      row.appendChild(errorCodeCell);
      row.appendChild(messageCell);

      tableBody.appendChild(row);
    });

    // Update pagination info if available
    if (metadata) {
      updatePaginationInfo(metadata);
    }
  }

  function formatTimestamp(timestamp) {
    if (!timestamp || timestamp === "N/A") return "N/A";

    try {
      const date = new Date(timestamp);
      if (isNaN(date.getTime())) return timestamp;

      // Format similar to ModSecurity: "29 Jun 12:00"
      const day = date.getDate();
      const month = date.toLocaleDateString("en-US", { month: "short" });
      const time = date.toLocaleTimeString("en-US", {
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });

      return `${day} ${month} ${time}`;
    } catch (error) {
      return timestamp;
    }
  }

  function updatePaginationInfo(metadata) {
    const paginationInfo = document.querySelector(".pagination-info");
    if (paginationInfo && metadata.total_count) {
      const start = (metadata.page - 1) * metadata.limit + 1;
      const end = Math.min(
        metadata.page * metadata.limit,
        metadata.total_count
      );
      paginationInfo.textContent = `Showing ${start}-${end} of ${metadata.total_count} entries`;
    }
  }

  // Chart functionality
  function initializeCharts() {
    // Create chart containers if they exist
    const severityCtx = document.getElementById("severityChart");
    const timelineCtx = document.getElementById("timelineChart");
    const modulesCtx = document.getElementById("modulesChart");
    const messagesCtx = document.getElementById("messagesChart");

    if (severityCtx) {
      charts.severity = new Chart(severityCtx, {
        type: "bar",
        data: {
          labels: [],
          datasets: [
            {
              label: "Count",
              data: [],
              backgroundColor: [],
            },
          ],
        },
        options: {
          responsive: true,
          indexAxis: "y",
          onClick: (event, elements) => {
            if (elements.length > 0) {
              const elementIndex = elements[0].index;
              const clickedSeverity = charts.severity.data.labels[elementIndex];
              handleSeveritySelection(clickedSeverity);
            }
          },
          onHover: (event, activeElements) => {
            event.native.target.style.cursor =
              activeElements.length > 0 ? "pointer" : "default";
          },
          plugins: {
            legend: { display: false },
            title: { display: true, text: "Severity Distribution" },
            tooltip: {
              callbacks: {
                afterLabel: function (context) {
                  return selectedSeverity === context.label
                    ? "(Click to remove filter)"
                    : "(Click to filter)";
                },
              },
            },
          },
          scales: {
            x: { beginAtZero: true },
          },
        },
      });
    }

    if (timelineCtx) {
      charts.timeline = new Chart(timelineCtx, {
        type: "line",
        data: {
          labels: [],
          datasets: [
            {
              label: "Errors",
              data: [],
              borderColor: "#ef4444",
              backgroundColor: "rgba(239, 68, 68, 0.1)",
              tension: 0.1,
            },
          ],
        },
        options: {
          responsive: true,
          plugins: {
            title: { display: true, text: "Error Count Over Time" },
          },
          scales: {
            y: { beginAtZero: true },
          },
        },
      });
    }

    if (modulesCtx) {
      charts.modules = new Chart(modulesCtx, {
        type: "bar",
        data: {
          labels: [],
          datasets: [
            {
              label: "Errors",
              data: [],
              backgroundColor: "#3b82f6",
            },
          ],
        },
        options: {
          responsive: true,
          plugins: {
            title: { display: true, text: "Top Modules by Error Count" },
          },
          scales: {
            y: { beginAtZero: true },
          },
        },
      });
    }

    if (messagesCtx) {
      charts.messages = new Chart(messagesCtx, {
        type: "bar",
        data: {
          labels: [],
          datasets: [
            {
              label: "Occurrences",
              data: [],
              backgroundColor: "#8b5cf6",
            },
          ],
        },
        options: {
          responsive: true,
          indexAxis: "y",
          plugins: {
            title: { display: true, text: "Most Frequent Error Messages" },
          },
          scales: {
            x: { beginAtZero: true },
          },
        },
      });
    }
  }

  // Function to get severity color matching the table badges
  function getSeverityColor(severity) {
    const severityColors = {
      emergency: "#ef4444", // Red (was working before)
      alert: "#ef4444", // Red
      critical: "#ef4444", // Red
      error: "#ef4444", // Red
      warning: "#f97316", // Orange (original shade)
      notice: "#eab308", // Yellow (original shade)
      info: "#3b82f6", // Blue (original shade)
      debug: "#6b7280", // Gray (original shade)
      unknown: "#6b7280", // Gray
    };

    return severityColors[severity.toLowerCase()] || "#6b7280";
  }

  function updateCharts(dashboardData) {
    // Update severity chart
    if (charts.severity && dashboardData.severity_distribution) {
      const severityData = dashboardData.severity_distribution;
      charts.severity.data.labels = severityData.map((item) => item.severity);
      charts.severity.data.datasets[0].data = severityData.map(
        (item) => item.count
      );
      // Update colors to match severity levels with filtering visual feedback
      charts.severity.data.datasets[0].backgroundColor = severityData.map(
        (item) => {
          const baseColor = getSeverityColor(item.severity);
          if (selectedSeverity && selectedSeverity !== item.severity) {
            return baseColor + "4D"; // Add 30% opacity for non-selected items
          } else if (selectedSeverity === item.severity) {
            return baseColor; // Full color for selected
          }
          return baseColor + "E6"; // Add 90% opacity for normal state
        }
      );
      // Update border for selected item
      charts.severity.data.datasets[0].borderColor = severityData.map(
        (item) => {
          return selectedSeverity === item.severity ? "#000000" : "transparent";
        }
      );
      charts.severity.data.datasets[0].borderWidth = selectedSeverity ? 2 : 0;

      // Update chart title to show active filter
      const chartTitle = selectedSeverity
        ? `Severity Distribution (Filtered: ${selectedSeverity})`
        : "Severity Distribution";
      charts.severity.options.plugins.title.text = chartTitle;

      charts.severity.update();
    }

    // Update timeline chart
    if (charts.timeline && dashboardData.timeline_data) {
      const timelineData = dashboardData.timeline_data;
      charts.timeline.data.labels = timelineData.map((item) => item.time);
      charts.timeline.data.datasets[0].data = timelineData.map(
        (item) => item.count
      );
      charts.timeline.update();
    }

    // Update modules chart
    if (charts.modules && dashboardData.top_modules) {
      const modulesData = dashboardData.top_modules.slice(0, 10);
      charts.modules.data.labels = modulesData.map((item) => item.module);
      charts.modules.data.datasets[0].data = modulesData.map(
        (item) => item.count
      );
      charts.modules.update();
    }

    // Update messages chart
    if (charts.messages && dashboardData.frequent_messages) {
      const messagesData = dashboardData.frequent_messages.slice(0, 10);
      const truncatedLabels = messagesData.map((item) =>
        item.message.length > 50
          ? item.message.substring(0, 50) + "..."
          : item.message
      );
      charts.messages.data.labels = truncatedLabels;
      charts.messages.data.datasets[0].data = messagesData.map(
        (item) => item.count
      );
      charts.messages.update();
    }
  }

  function handleSeveritySelection(clickedSeverity) {
    if (selectedSeverity === clickedSeverity) {
      // Clicking the same severity removes the filter
      selectedSeverity = null;
    } else {
      // Clicking a different severity sets the filter
      selectedSeverity = clickedSeverity;
    }

    // Update the severity input filter to match the selection
    const severityInput = document.querySelector('[data-column="severity"]');
    if (severityInput) {
      severityInput.value = selectedSeverity || "";
    }

    // Filter the table data and re-render
    filterAndRenderTable();

    // Update charts to reflect the visual change
    updateCharts(currentDashboardData);
  }

  function filterAndRenderTable() {
    applyFilters();
  }

  function applyFilters() {
    if (!logData || logData.length === 0) return;

    filteredData = logData.filter((entry) => {
      // Check timestamp range filter first
      if (!isTimestampInRange(entry.timestamp)) {
        return false;
      }

      // Apply severity filter if one is selected
      if (selectedSeverity) {
        const logSeverity = (entry.severity || "").toLowerCase();
        if (logSeverity !== selectedSeverity.toLowerCase()) {
          return false;
        }
      }

      return true;
    });

    // Apply current sorting if any
    if (currentSort.column) {
      applySorting(currentSort.column, currentSort.direction, false);
    }

    // Re-render the table with filtered data
    renderApacheErrorTable(filteredData, {
      total_count: filteredData.length,
      page: 1,
      limit: filteredData.length,
    });

    // Update record counts
    updateRecordCounts();
  }

  function isTimestampInRange(timestamp) {
    if (!timestampFilter.start || !timestampFilter.end) {
      return true;
    }

    // Convert timestamps to Date objects for proper comparison
    try {
      const logDate = new Date(timestamp);
      const startDate = new Date(timestampFilter.start);
      const endDate = new Date(timestampFilter.end);

      // If any date is invalid, fall back to string comparison
      if (
        isNaN(logDate.getTime()) ||
        isNaN(startDate.getTime()) ||
        isNaN(endDate.getTime())
      ) {
        return (
          timestamp >= timestampFilter.start && timestamp <= timestampFilter.end
        );
      }

      return logDate >= startDate && logDate <= endDate;
    } catch (error) {
      // Fall back to string comparison if date parsing fails
      return (
        timestamp >= timestampFilter.start && timestamp <= timestampFilter.end
      );
    }
  }

  function clearCharts() {
    Object.values(charts).forEach((chart) => {
      if (chart && chart.data) {
        chart.data.labels = [];
        chart.data.datasets.forEach((dataset) => (dataset.data = []));
        chart.update();
      }
    });
  }

  function handleApacheFileUpload() {
    const file = fileUpload.files[0];
    if (!file) return;

    // Validate file size (300MB limit)
    const maxSize = 300 * 1024 * 1024; // 300MB
    if (file.size > maxSize) {
      alert("File size exceeds 300MB limit. Please select a smaller file.");
      fileUpload.value = "";
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    // Show upload progress
    const uploadButton = document.querySelector(".upload-button");
    const originalHTML = uploadButton.innerHTML;
    uploadButton.innerHTML = "<span>Uploading...</span>";
    uploadButton.style.pointerEvents = "none";

    fetch("/api/apache-error/upload", {
      method: "POST",
      body: formData,
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          // Refresh file list
          loadApacheErrorFiles();

          // Show success message briefly
          uploadButton.innerHTML = "<span>✓ Uploaded</span>";
          setTimeout(() => {
            uploadButton.innerHTML = originalHTML;
            uploadButton.style.pointerEvents = "";
          }, 2000);

          // Select the new file automatically
          setTimeout(() => {
            fileSelect.value = data.filename;
            loadApacheErrorData(data.filename);
          }, 500);
        } else {
          alert(data.error || "Upload failed");
          uploadButton.innerHTML = originalHTML;
          uploadButton.style.pointerEvents = "";
        }
      })
      .catch((error) => {
        console.error("Upload error:", error);
        alert("Upload failed: " + error.message);
        uploadButton.innerHTML = originalHTML;
        uploadButton.style.pointerEvents = "";
      });

    // Clear the input
    fileUpload.value = "";
  }

  // Global function to show message modal (simplified)
  window.showLogDetails = function (index) {
    if (!currentLogs[index]) return;

    const log = currentLogs[index];
    const messageModal = document.getElementById("messageModal");
    const messageModalBody = document.getElementById("messageModalBody");

    if (messageModal && messageModalBody) {
      messageModalBody.textContent = log.message || "No message available";
      messageModal.classList.add("active");
    }
  };

  // Function to close message modal
  window.closeMessageModal = function () {
    const messageModal = document.getElementById("messageModal");
    if (messageModal) {
      messageModal.classList.remove("active");
    }
  };

  // Event listeners
  if (fileSelect) {
    fileSelect.addEventListener("change", (e) => {
      const filename = e.target.value;
      if (filename) {
        loadApacheErrorData(filename);
      }
    });
  }

  if (fileUpload) {
    fileUpload.addEventListener("change", handleApacheFileUpload);
  }

  // Add event listener for severity column input filter
  const severityInput = document.querySelector('[data-column="severity"]');
  if (severityInput) {
    severityInput.addEventListener("input", (e) => {
      const value = e.target.value.toLowerCase().trim();

      // Update selectedSeverity to match the input
      if (value === "") {
        selectedSeverity = null;
      } else {
        // Find matching severity from current data
        const matchingSeverity =
          currentDashboardData.severity_distribution?.find((item) =>
            item.severity.toLowerCase().includes(value)
          );
        selectedSeverity = matchingSeverity ? matchingSeverity.severity : value;
      }

      // Filter and re-render table
      filterAndRenderTable();

      // Update chart visual feedback
      updateCharts(currentDashboardData);
    });
  }

  // Add sorting event listeners
  if (sortableHeaders) {
    sortableHeaders.forEach((header) => {
      header.addEventListener("click", (e) => {
        const column = e.target
          .closest(".sortable-header")
          .getAttribute("data-column");
        let direction = "asc";

        if (currentSort.column === column && currentSort.direction === "asc") {
          direction = "desc";
        }

        currentSort = { column, direction };
        applySorting(column, direction);
      });
    });
  }

  function applySorting(column, direction, updateData = true) {
    currentSort = { column, direction };

    filteredData.sort((a, b) => {
      let aVal, bVal;

      if (column === "timestamp") {
        // Convert timestamps to Date objects for proper sorting
        aVal = new Date(a[column]);
        bVal = new Date(b[column]);
        // If date parsing fails, fall back to string comparison
        if (isNaN(aVal.getTime()) || isNaN(bVal.getTime())) {
          aVal = a[column] || "";
          bVal = b[column] || "";
        }
      } else if (column === "pid" || column === "error_code") {
        aVal = parseInt(a[column]) || 0;
        bVal = parseInt(b[column]) || 0;
      } else if (column === "client_ip") {
        // Sort by combined client IP + port
        const aClient =
          (a.client_ip || "") + (a.client_port ? `:${a.client_port}` : "");
        const bClient =
          (b.client_ip || "") + (b.client_port ? `:${b.client_port}` : "");
        aVal = aClient.toLowerCase();
        bVal = bClient.toLowerCase();
      } else {
        aVal = (a[column] || "").toString().toLowerCase();
        bVal = (b[column] || "").toString().toLowerCase();
      }

      if (direction === "asc") {
        return aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
      } else {
        return aVal > bVal ? -1 : aVal < bVal ? 1 : 0;
      }
    });

    if (updateData) {
      renderApacheErrorTable(filteredData, {
        total_count: filteredData.length,
        page: 1,
        limit: filteredData.length,
      });
    }

    // Update sort indicators
    document.querySelectorAll(".sortable-header .sort-icon").forEach((icon) => {
      icon.textContent = "↕";
    });

    const currentHeader = document.querySelector(
      `[data-column="${column}"] .sort-icon`
    );
    if (currentHeader) {
      currentHeader.textContent = direction === "asc" ? "↑" : "↓";
    }
  }

  // Add chart click handlers for filtering (placeholder for future enhancement)
  function addChartClickHandlers() {
    // TODO: Implement filtering when charts are clicked
    // This will be part of the filtering tasks (Tasks 27-35)
  }

  // Function to format timestamps for slider display (readable format)
  function formatTimestampForSlider(timestamp) {
    if (!timestamp || timestamp === "N/A") return timestamp;

    try {
      let date;
      if (typeof timestamp === "string") {
        if (timestamp.includes("T")) {
          // ISO format
          date = new Date(timestamp);
        } else {
          // Try to parse other formats
          date = new Date(timestamp);
        }
      } else {
        date = new Date(timestamp);
      }

      if (isNaN(date.getTime())) return timestamp;

      // Format like "30 Jun 00:03"
      const day = date.getDate();
      const month = date.toLocaleDateString("en-US", { month: "short" });
      const time = date.toLocaleTimeString("en-US", {
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });

      return `${day} ${month} ${time}`;
    } catch (error) {
      return timestamp;
    }
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

    // Set up initial values with formatted timestamps
    document.getElementById("startValue").textContent =
      formatTimestampForSlider(timestampRange.min);
    document.getElementById("endValue").textContent = formatTimestampForSlider(
      timestampRange.max
    );

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
      .map((log) => log.timestamp)
      .filter((ts) => ts !== "N/A")
      .sort();

    if (timestamps.length === 0) return;

    const startIndex = Math.floor((startValue / 100) * (timestamps.length - 1));
    const endIndex = Math.floor((endValue / 100) * (timestamps.length - 1));

    timestampFilter.start = timestamps[startIndex];
    timestampFilter.end = timestamps[endIndex];

    // Update display values with formatted timestamps
    document.getElementById("startValue").textContent =
      formatTimestampForSlider(timestampFilter.start);
    document.getElementById("endValue").textContent = formatTimestampForSlider(
      timestampFilter.end
    );

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

    // Update display with formatted timestamps
    document.getElementById("startValue").textContent =
      formatTimestampForSlider(timestampRange.min);
    document.getElementById("endValue").textContent = formatTimestampForSlider(
      timestampRange.max
    );

    // Update visual range
    updateSliderRange();

    // Apply filters and update button
    applyFilters();
    updateResetButton();
  }

  function updateRecordCounts() {
    const totalRecordsElement = document.getElementById("totalRecords");
    const filteredRecordsElement = document.getElementById("filteredRecords");

    if (totalRecordsElement && filteredRecordsElement) {
      totalRecordsElement.textContent = logData.length.toLocaleString();
      filteredRecordsElement.textContent = filteredData.length.toLocaleString();
    }
  }

  // Load initial state
  loadApacheErrorFiles();

  // Theme toggle functionality (copied from main app.js)
  function initializeThemeToggle() {
    const themeToggle = document.getElementById("themeToggle");
    if (!themeToggle) return;

    const savedTheme = localStorage.getItem("theme") || "light";

    function setTheme(theme) {
      document.documentElement.setAttribute("data-theme", theme);
      localStorage.setItem("theme", theme);

      const themeText = themeToggle.querySelector(".theme-text");
      if (themeText) {
        themeText.textContent = theme === "dark" ? "Light Mode" : "Dark Mode";
      }
    }

    setTheme(savedTheme);

    themeToggle.addEventListener("click", function () {
      const currentTheme = document.documentElement.getAttribute("data-theme");
      const newTheme = currentTheme === "dark" ? "light" : "dark";
      setTheme(newTheme);
    });
  }

  // Sidebar functionality (copied from main app.js)
  function initializeSidebar() {
    const sidebar = document.getElementById("sidebar");
    const sidebarToggle = document.getElementById("sidebarToggle");

    if (!sidebar || !sidebarToggle) return;

    function loadSidebarState() {
      const isCollapsed = localStorage.getItem("sidebarCollapsed") === "true";
      if (isCollapsed) {
        sidebar.classList.add("collapsed");
      }
      return isCollapsed;
    }

    function saveSidebarState() {
      const isCollapsed = sidebar.classList.contains("collapsed");
      localStorage.setItem("sidebarCollapsed", isCollapsed);
    }

    function toggleSidebar() {
      sidebar.classList.toggle("collapsed");
      saveSidebarState();
    }

    function handleResponsiveSidebar() {
      const isDesktop = window.innerWidth > 992;
      if (!isDesktop) {
        sidebar.classList.add("collapsed");
      } else {
        loadSidebarState();
      }

      sidebarToggle.style.display = isDesktop ? "flex" : "none";
    }

    loadSidebarState();
    handleResponsiveSidebar();

    sidebarToggle.addEventListener("click", toggleSidebar);
    window.addEventListener("resize", handleResponsiveSidebar);
  }

  // Mobile menu functionality (copied from main app.js)
  function initializeMobileMenu() {
    const mobileMenuButton = document.getElementById("mobileMenuButton");
    const sidebarOverlay = document.getElementById("sidebarOverlay");
    const sidebar = document.getElementById("sidebar");

    if (!mobileMenuButton || !sidebarOverlay || !sidebar) return;

    function toggleMobileMenu() {
      const isOpen = sidebar.classList.contains("mobile-open");

      if (isOpen) {
        sidebar.classList.remove("mobile-open");
        sidebarOverlay.classList.remove("active");
        document.body.style.overflow = "";
      } else {
        sidebar.classList.add("mobile-open");
        sidebarOverlay.classList.add("active");
        document.body.style.overflow = "hidden";
      }
    }

    mobileMenuButton.addEventListener("click", toggleMobileMenu);
    sidebarOverlay.addEventListener("click", toggleMobileMenu);
  }
});

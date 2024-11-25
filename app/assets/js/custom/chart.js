export async function renderAnomaliesChart(apiUrl, canvasId, refreshInterval) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    let anomaliesChart = null;

    async function updateAnomaliesChart() {
        try {
            const response = await fetch(apiUrl);
            const data = await response.json();

            // Process the data to group by anomaly type
            const anomalyCounts = data.reduce((counts, anomaly) => {
                counts[anomaly.anomaly_type] = (counts[anomaly.anomaly_type] || 0) + 1;
                return counts;
            }, {});

            // Prepare data for Chart.js
            const labels = Object.keys(anomalyCounts);
            const values = Object.values(anomalyCounts);

            if (anomaliesChart) {
                // Update the chart data
                anomaliesChart.data.labels = labels;
                anomaliesChart.data.datasets[0].data = values;
                anomaliesChart.update();
            } else {
                // Create the chart
                anomaliesChart = new Chart(ctx, {
                    type: 'pie',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Anomalies',
                            data: values,
                            backgroundColor: [
                                'rgba(255, 99, 132, 0.6)',
                                'rgba(54, 162, 235, 0.6)',
                                'rgba(255, 206, 86, 0.6)',
                                'rgba(75, 192, 192, 0.6)',
                                'rgba(153, 102, 255, 0.6)',
                                'rgba(255, 159, 64, 0.6)'
                            ],
                            borderColor: [
                                'rgba(255, 99, 132, 1)',
                                'rgba(54, 162, 235, 1)',
                                'rgba(255, 206, 86, 1)',
                                'rgba(75, 192, 192, 1)',
                                'rgba(153, 102, 255, 1)',
                                'rgba(255, 159, 64, 1)'
                            ],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        aspectRation:2,
                        plugins: {
                            legend: {
                                position: 'top',
                            }
                        }
                    }
                });
            }
        } catch (error) {
            console.error('Error updating Anomalies Chart:', error);
        }
    }

    // Initial render and periodic updates
    await updateAnomaliesChart();

    setInterval(updateAnomaliesChart, refreshInterval * 1000);
}

export async function renderDataRateChart(apiUrl, canvasId, refreshInterval, batchSize) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    let dataRateChart = null;
    console.log("batchSize", batchSize);
    async function updateDataRateChart() {
        try {
            const response = await fetch(`${apiUrl}?batch=${encodeURIComponent(batchSize)}`);
            const result = await response.json();

    
            const dataRates = result.data; 
            const labels = result.labels; 
            const average = result.average;

            if (dataRateChart) {
                // Update the chart data
                dataRateChart.data.labels = labels.reverse(); 
                dataRateChart.data.datasets[0].data = dataRates.reverse();
                dataRateChart.data.datasets[1].data = new Array(labels.length).fill(average); 
                dataRateChart.update();
            } else {
                // Create the chart
                dataRateChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels.reverse(), // Initial labels
                        datasets: [
                            {
                                label: 'Data Rate (bytes/sec)',
                                data: dataRates.reverse(), // Initial data
                                borderColor: 'rgba(75, 192, 192, 1)',
                                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                                borderWidth: 2,
                                fill: true,
                            },
                            {
                                label: 'Average Data Rate',
                                data: new Array(labels.length).fill(average),
                                borderColor: 'rgba(255, 99, 132, 1)',
                                borderDash: [5, 5],
                                borderWidth: 2,
                                fill: false,
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: {
                                display: true,
                                position: 'top',
                            },
                        },
                        scales: {
                            x: {
                                title: {
                                    display: true,
                                    text: 'Time',
                                }
                            },
                            y: {
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: 'Data Rate (bytes/sec)',
                                }
                            }
                        }
                    }
                });
            }
        } catch (error) {
            console.error('Error updating Data Rate Chart:', error);
        }
    }

    // Initial render and periodic updates
    await updateDataRateChart();

    setInterval(updateDataRateChart, refreshInterval * 1000);
}

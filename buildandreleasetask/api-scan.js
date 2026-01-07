const tl = require('azure-pipelines-task-lib/task');
const axios = require('axios');

// API endpoint for triggering API scans - configurable via environment or default to your rescan API
const API_SCAN_URL = process.env.SEC1_API_SCAN_URL || 'https://api.sec1.io/dast/rescan';

/**
 * Trigger API scan after deployment
 * This is a standalone module that can be called after any deployment strategy
 */
async function triggerApiScan() {
    const configId = tl.getInput('apiScanConfigId', false);
    const scanMode = tl.getInput('apiScanMode', false) || 'async';
    const timeoutMinutes = parseInt(tl.getInput('apiScanTimeout', false) || '10');
    
    if (!configId) {
        console.log('⚠️ API scan configuration ID not provided, skipping API scan');
        return { skipped: true, reason: 'No configuration ID' };
    }
    
    console.log(`🔍 Starting API security scan...`);
    console.log(`⚙️ Configuration ID: ${configId}`);
    console.log(`🔄 Scan Mode: ${scanMode}`);
    
    try {
        const serviceConnectionId = tl.getInput('serviceConnection', true);
        const apiKey = getServiceConnectionPassword(serviceConnectionId);
        
        const scanResult = await initiateApiScan(apiKey, configId, scanMode, timeoutMinutes);
        
        // Set pipeline variables for downstream tasks - using proper Azure DevOps format
        if (scanResult.reportId) {
            console.log(`##vso[task.setvariable variable=SEC1_API_SCAN_REPORT_ID]${scanResult.reportId}`);
            process.env.SEC1_API_SCAN_REPORT_ID = scanResult.reportId;
        }
        if (scanResult.reportUrl) {
            console.log(`##vso[task.setvariable variable=SEC1_API_SCAN_REPORT_URL]${scanResult.reportUrl}`);
            process.env.SEC1_API_SCAN_REPORT_URL = scanResult.reportUrl;
        }
        
        return scanResult;
        
    } catch (error) {
        console.error('❌ API scan failed:', error.message);
        
        // Check if we should fail the pipeline on API scan errors
        const failOnApiScanError = tl.getBoolInput('failOnApiScanError', false);
        if (failOnApiScanError) {
            throw error;
        } else {
            console.log('🔄 Continuing pipeline despite API scan failure');
            return { failed: true, error: error.message };
        }
    }
}

/**
 * Initiate the API scan with Sec1 platform
 */
async function initiateApiScan(apiKey, configId, scanMode, timeoutMinutes) {
    // Simple payload - only configId needed for your rescan API
    const scanPayload = {
        configId: configId
    };
    
    console.log('🚀 Triggering API rescan...');
    
    try {
        const response = await axios.post(API_SCAN_URL, scanPayload, {
            headers: {
                'sec1-api-key': apiKey,
                'Content-Type': 'application/json',
                'User-Agent': 'Sec1-AzureDevOps-Extension/1.2.1',
                'x-user-id': 'dinesh.rawat@sec1.io'
            },
            timeout: 30000 // 30 second timeout for initial request
        });
        
        console.log(`✅ API rescan triggered successfully`);
        console.log(`📊 Response:`, response.data);
        
        // Handle your actual rescan API response format - it's an array
        const responseData = Array.isArray(response.data) ? response.data[0] : response.data;
        const reportId = responseData.uuid || responseData.reportId || responseData.id || 'unknown';
        const configId = responseData.configId;
        const applicationName = responseData.applicationName;
        const location = responseData.location;
        const message = responseData.message;
        
        console.log(`📋 Scan UUID: ${reportId}`);
        console.log(`🏷️ Application: ${applicationName}`);
        console.log(`🌐 Target: ${location}`);
        console.log(`💬 Status: ${message}`);
        
        if (scanMode === 'async') {
            console.log(`🔄 Asynchronous scan initiated - pipeline will continue`);
            
            return {
                reportId,
                mode: 'async',
                status: 'triggered',
                applicationName,
                location,
                configId,
                reportUrl: reportId !== 'unknown' ? `https://unified.sec1.io/reports/${reportId}` : undefined
            };
        } else {
            // Synchronous mode - wait for completion
            console.log(`⏳ Waiting for API scan to complete (timeout: ${timeoutMinutes} minutes)...`);
            return await waitForScanCompletion(apiKey, reportId, timeoutMinutes);
        }
        
    } catch (error) {
        if (error.response) {
            // API responded with error
            console.error(`❌ API scan request failed: ${error.response.status} ${error.response.statusText}`);
            console.error(`Response: ${JSON.stringify(error.response.data, null, 2)}`);
            throw new Error(`API scan failed: ${error.response.data.message || error.response.statusText}`);
        } else if (error.request) {
            // Network error
            console.error('❌ Network error while triggering API scan');
            throw new Error('Failed to connect to Sec1 API. Please check network connectivity.');
        } else {
            throw error;
        }
    }
}

/**
 * Wait for synchronous scan completion
 */
async function waitForScanCompletion(apiKey, reportId, timeoutMinutes) {
    const maxAttempts = timeoutMinutes * 6; // Check every 10 seconds
    let attempts = 0;
    
    while (attempts < maxAttempts) {
        await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds
        attempts++;
        
        try {
            // Use your actual status check API with correct payload format
            const statusResponse = await axios.post('https://api.sec1.io/dast/api/asset/report/status', {
                reportId: [reportId]  // Array format as per your API
            }, {
                headers: {
                    'sec1-api-key': apiKey,
                    'Content-Type': 'application/json',
                    'User-Agent': 'Sec1-AzureDevOps-Extension/1.2.1',
                    'x-user-id': 'dinesh.rawat@sec1.io'
                },
                timeout: 15000
            });
            
            // Handle your actual status API response format - it's an array
            const statusData = Array.isArray(statusResponse.data) ? statusResponse.data[0] : statusResponse.data;
            const { scanStatus, scanProgress, scanProgressReport, critical, high, medium, low, total } = statusData;
            
            console.log(`📊 Scan status: ${scanStatus} (${scanProgress}%) - ${scanProgressReport} - ${attempts * 10}s elapsed`);
            
            if (scanStatus === 'COMPLETED') {
                console.log(`✅ API scan completed successfully`);
                
                // Display vulnerability summary
                console.log(`\n🎯 ================== API SCAN RESULTS ==================`);
                console.log(`📊 Report ID: ${statusData.reportId}`);
                console.log(`🏷️ Application: ${statusData.applicationName}`);
                console.log(`📅 Scan Date: ${statusData.scanDateTime}`);
                console.log(`🔗 Assets Found: ${statusData.assetsCount}`);
                console.log(`\n📈 Vulnerability Summary:`);
                console.log(`   🔴 Critical: ${critical}`);
                console.log(`   🟠 High: ${high}`);
                console.log(`   🟡 Medium: ${medium}`);
                console.log(`   🔵 Low: ${low}`);
                console.log(`   📊 Total: ${total}`);
                console.log(`🎯 ================================================\n`);
                
                // Check thresholds
                checkApiScanThresholds({ critical, high, medium, low });
                
                return {
                    reportId,
                    mode: 'sync',
                    status: 'completed',
                    reportUrl: `https://unified.sec1.io/api-security-advanced-dashboard/${reportId}`,
                    summary: { critical, high, medium, low, total },
                    vulnerabilities: [],
                    applicationName: statusData.applicationName,
                    assetsCount: statusData.assetsCount,
                    scanDateTime: statusData.scanDateTime
                };
                
            } else if (scanStatus === 'FAILED' || scanStatus === 'ERROR') {
                throw new Error(`API scan failed with status: ${scanStatus}`);
            }
            
            // Status is still RUNNING or QUEUED, continue waiting
            
        } catch (error) {
            if (error.response && error.response.status === 404) {
                throw new Error(`Scan report ${reportId} not found`);
            }
            console.error(`❌ Error checking scan status: ${error.message}`);
            
            // Continue waiting for transient errors
            if (attempts >= maxAttempts - 1) {
                throw error;
            }
        }
    }
    
    // Timeout reached
    console.warn(`⏰ API scan timeout reached (${timeoutMinutes} minutes)`);
    console.log(`📋 Scan may still be running. Check status at: https://unified.sec1.io/reports/${reportId}`);
    
    return {
        reportId,
        mode: 'sync',
        status: 'timeout',
        reportUrl: `https://unified.sec1.io/reports/${reportId}`
    };
}

/**
 * Display API scan results in a formatted way
 */
function displayApiScanResults(report) {
    console.log(`\n🎯 ================== API SCAN RESULTS ==================`);
    console.log(`📊 Report ID: ${report.reportId}`);
    console.log(`🌐 Target URL: ${report.targetUrl}`);
    console.log(`⏰ Scan Duration: ${report.duration || 'N/A'}`);
    
    if (report.summary) {
        const { critical, high, medium, low, info } = report.summary;
        const total = critical + high + medium + low + (info || 0);
        
        console.log(`\n📈 Vulnerability Summary:`);
        console.log(`   🔴 Critical: ${critical}`);
        console.log(`   🟠 High: ${high}`);
        console.log(`   🟡 Medium: ${medium}`);
        console.log(`   🔵 Low: ${low}`);
        if (info) console.log(`   ℹ️  Info: ${info}`);
        console.log(`   📊 Total: ${total}`);
        
        // Check API scan thresholds (similar to SCA/SAST)
        checkApiScanThresholds(report.summary);
    }
    
    if (report.reportUrl) {
        console.log(`\n📄 Detailed Report: ${report.reportUrl}`);
    }
    
    console.log(`🎯 ================================================\n`);
}

/**
 * Check API scan results against thresholds
 */
function checkApiScanThresholds(summary) {
    const apiThresholds = {
        critical: parseInt(tl.getInput('critical', false) || '999'),
        high: parseInt(tl.getInput('high', false) || '999'),
        medium: parseInt(tl.getInput('medium', false) || '999'),
        low: parseInt(tl.getInput('low', false) || '999')
    };
    
    let thresholdExceeded = false;
    
    Object.keys(apiThresholds).forEach(severity => {
        const count = summary[severity] || 0;
        const threshold = apiThresholds[severity];
        
        if (count > threshold) {
            console.error(`❌ API scan threshold exceeded for ${severity}: ${count} > ${threshold}`);
            thresholdExceeded = true;
        } else {
            console.log(`✅ API scan ${severity} threshold met: ${count} <= ${threshold}`);
        }
    });
    
    if (thresholdExceeded) {
        const failOnThreshold = tl.getBoolInput('thresholdCheck', false);
        if (failOnThreshold) {
            throw new Error('API scan vulnerability thresholds exceeded');
        } else {
            console.warn('⚠️ API scan thresholds exceeded but pipeline will continue');
        }
    }
}

/**
 * Get service connection password (API key)
 */
function getServiceConnectionPassword(serviceConnectionId) {
    try {
        const endpointAuth = tl.getEndpointAuthorization(serviceConnectionId, false);
        return endpointAuth.parameters.password;
    } catch (error) {
        throw new Error('Failed to retrieve API key from service connection');
    }
}

/**
 * Standalone function to trigger API scan manually
 * Useful for custom deployment scenarios
 */
async function triggerApiScanManual(configId, apiKey, mode = 'async') {
    if (!configId || !apiKey) {
        throw new Error('Config ID and API key are required for manual API scan trigger');
    }
    
    // Simple payload - only configId needed for your rescan API
    const scanPayload = {
        configId: configId
    };
    
    console.log(`🔍 Manual API Scan`);
    console.log(`⚙️ Using Config ID: ${configId}`);
    
    try {
        const response = await axios.post(API_SCAN_URL, scanPayload, {
            headers: {
                'sec1-api-key': apiKey,
                'Content-Type': 'application/json',
                'User-Agent': 'Sec1-AzureDevOps-Extension/1.2.1'
            }
        });
        
        console.log(`✅ Manual API rescan triggered`);
        console.log(`📊 Response:`, response.data);
        
        return response.data;
        
    } catch (error) {
        console.error(`❌ Manual API scan failed: ${error.message}`);
        throw error;
    }
}

module.exports = {
    triggerApiScan,
    triggerApiScanManual
};
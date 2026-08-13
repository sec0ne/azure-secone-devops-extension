const tl = require('azure-pipelines-task-lib/task');
const axios = require('axios');

// ANSI escape codes for colors
const redColor = '\x1b[31m';
const greenColor = '\x1b[32m';
const resetColor = '\x1b[0m';
const darkAmberColor = '\x1b[33m';
const startIcon = "\u25B6"; // Unicode character for black right-pointing triangle
const greenTickIcon = "\x1b[32m\u2714\x1b[0m";
const redCrossIcon = "\x1b[31m\u2716\x1b[0m"; // Red cross icon (using ASCII escape sequence)
const boldText = "\x1b[1m"; // ASCII escape sequence for bold text
const infoIcon = "\u2139"; // Unicode information source character

const scaApiUrl = 'https://api.sec1.io/rest/foss/ascan?enableSbom=true'; // SCA scan trigger endpoint (URL-based)
const scaStatusUrl = 'https://api.sec1.io/foss/report/status'; // SCA scan status polling endpoint
const sastApiUrl = 'https://api.sec1.io/foss/sast/ascan'; // SAST async scan trigger endpoint
const sastStatusUrl = 'https://api.sec1.io/sast/asset/report/status'; // SAST scan status polling endpoint
const dastApiUrl = 'https://api.sec1.io/aidast/api/rescan'; // DAST trigger endpoint
const apiSecurityApiUrl = 'https://api.sec1.io/dast/rescan'; // API Security trigger endpoint (config-id based)
const dashboardUrl = 'https://unified.sec1.io'; // Sec1 dashboard base URL

const SCA_POLL_INTERVAL_MS = 10000; // poll status every 10s
const SCA_POLL_MAX_DURATION_MS = 30 * 60 * 1000; // give up after 30 minutes

const SAST_POLL_INTERVAL_MS = 10000; // poll status every 10s
const SAST_POLL_MAX_DURATION_MS = 30 * 60 * 1000; // give up after 30 minutes


async function run() {
    try {
        console.log(`${startIcon} ${boldText}Sec1 Security Scanner Started ...${resetColor}`);

        // Final results processing
        let finalResult = tl.TaskResult.Succeeded;
        let resultMessage = 'Sec1 Security Scanner task completed successfully';
        let scaPassed = true
        let sastPassed = true
        let dastPassed = true
        let apiSecurityPassed = true

        //Read all input and carry out validation
        const inputs = await readInputs();
        if (inputs.enableSCA) {
            console.log(`${startIcon}${startIcon} Initiating Sec1 SCA Scanner ...${resetColor}`);
            //Trigger SCA Scan
            const scaResults = await triggerSCAScan(inputs);
            if (scaResults && scaResults.status === 'FAILED') {
                scaPassed = false;
                finalResult = tl.TaskResult.Failed;
            }
        } else {
            console.log(`${infoIcon} Sec1 SCA Scanner is disabled. Skipping...${resetColor}`);
        }

        if (inputs.enableSAST) {
            console.log(`${startIcon}${startIcon} Initiating Sec1 SAST Scanner ...${resetColor}`);
            //Trigger SAST Scan
            const sastResults = await triggerSASTScan(inputs);
            if (sastResults && sastResults.status === 'FAILED') {
                sastPassed = false
                finalResult = tl.TaskResult.Failed;
            }
        } else {
            console.log(`${infoIcon} Sec1 SAST Scanner is disabled. Skipping...${resetColor}`);
        }

        if (inputs.enableDAST) {
            console.log(`${startIcon}${startIcon} Initiating Sec1 DAST Scanner ...${resetColor}`);
            const dastResults = await triggerDASTScan(inputs);
            if (dastResults && dastResults.status === 'FAILED') {
                dastPassed = false
                finalResult = tl.TaskResult.Failed;
            }
        } else {
            console.log(`${infoIcon} Sec1 DAST Scanner is disabled. Skipping...${resetColor}`);
        }

        if (inputs.enableApiSecurity) {
            console.log(`${startIcon}${startIcon} Initiating Sec1 API Security Scanner ...${resetColor}`);
            const apiSecurityResults = await triggerApiSecurityScan(inputs);
            if (apiSecurityResults && apiSecurityResults.status === 'FAILED') {
                apiSecurityPassed = false
                finalResult = tl.TaskResult.Failed;
            }
        } else {
            console.log(`${infoIcon} Sec1 API Security Scanner is disabled. Skipping...${resetColor}`);
        }

        const failedScans = [];
        if (!scaPassed) failedScans.push('SCA');
        if (!sastPassed) failedScans.push('SAST');
        if (!dastPassed) failedScans.push('DAST');
        if (!apiSecurityPassed) failedScans.push('API Security');
        if (failedScans.length > 0) {
            resultMessage = `Sec1 ${failedScans.join(' & ')} Scan failed`;
        }
        tl.setResult(finalResult, resultMessage);
    } catch (error) {
        console.error(`${redCrossIcon} Error in Sec1 Security Scanner: ${error.message}`);
        tl.setResult(tl.TaskResult.Failed, error.message);
    }
}

async function readInputs() {
    const serviceConnectionId = tl.getInput('serviceConnection', true) || '';
    if (!serviceConnectionId) {
        throw new Error('Service connection not found or authorization details missing.');
    }

    const enableSCA = tl.getBoolInput('enableSCA', true);
    const enableSAST = tl.getBoolInput('enableSAST', true);
    const enableDAST = tl.getBoolInput('enableDAST', false);
    const enableApiSecurity = tl.getBoolInput('enableApiSecurity', false);
    if (!enableSCA && !enableSAST && !enableDAST && !enableApiSecurity) {
        throw new Error('At least one scan type (SCA, SAST, DAST or API Security) must be enabled.');
    }

    let dastTargetUrl = '';
    let dastScanType = 'quick';
    if (enableDAST) {
        dastTargetUrl = (tl.getInput('dastTargetUrl', false) || '').trim();
        if (!dastTargetUrl) {
            throw new Error('DAST Target URL is required when DAST scan is enabled.');
        }
        if (!/^https?:\/\//i.test(dastTargetUrl)) {
            throw new Error('DAST Target URL must start with http:// or https://');
        }
        const rawScanType = (tl.getInput('dastScanType', false) || 'quick').trim().toLowerCase();
        if (rawScanType !== 'quick' && rawScanType !== 'deep') {
            throw new Error(`Invalid DAST Scan Type '${rawScanType}'. Allowed values are 'quick' or 'deep'.`);
        }
        dastScanType = rawScanType;
    }

    let apiSecurityConfigId = '';
    if (enableApiSecurity) {
        apiSecurityConfigId = (tl.getInput('apiSecurityConfigId', false) || '').trim();
        if (!apiSecurityConfigId) {
            throw new Error('API Security Config ID is required when API Security scan is enabled.');
        }
    }

    const apiKey = getServiceConnectionPassword(serviceConnectionId);

    const repoUrl = tl.getVariable('Build.Repository.Uri');
    if (!repoUrl) {
        throw new Error('Build.Repository.Uri is not available. This task must run in a build pipeline with a checked-out repository.');
    }
    // Use the branch the pipeline is running against (Build.SourceBranch),
    // stripping the refs/heads/ prefix. If it is unset, branchName stays blank
    // and the Sec1 backend clones the repository's default branch.
    const fullBranchName = tl.getVariable('Build.SourceBranch') || '';
    const branchName = fullBranchName.replace('refs/heads/', '');

    const thresholdCheckInput = tl.getInput('thresholdCheck', true) || 'false';
    const thresholdCheck = thresholdCheckInput.toLowerCase() === 'true';

    // Async (fire-and-forget) SCA only applies when there is no threshold gate to evaluate —
    // a threshold check needs scan results, so it forces a synchronous poll.
    const asyncScan = tl.getBoolInput('asyncScan', false) && !thresholdCheck;

    const critical = validateThreshold(tl.getInput('critical'));
    const high = validateThreshold(tl.getInput('high'));
    const medium = validateThreshold(tl.getInput('medium'));
    const low = validateThreshold(tl.getInput('low'));

    // Get tag input, default to branchName if not provided, then 'default' if branchName is also null
    const tag = tl.getInput('tag') || branchName || 'default';

    return {
        apiKey,
        repoUrl,
        branchName,
        thresholdCheck,
        thresholds: { critical, high, medium, low },
        enableSCA,
        enableSAST,
        enableDAST,
        dastTargetUrl,
        dastScanType,
        enableApiSecurity,
        apiSecurityConfigId,
        asyncScan,
        tag
    };
}

function getServiceConnectionPassword(serviceConnectionId) {
    const serviceConnection = tl.getEndpointAuthorization(serviceConnectionId, false);
    if (!serviceConnection) {
        throw new Error('Service connection not found or authorization details missing.');
    }
    return serviceConnection.parameters['password'];
}

// Derive the application name from the SCM URL: everything after the host[:port]/
// e.g. https://dev.azure.com/org/project/_git/repo -> org/project/_git/repo
function getAppNameFromUrl(scmUrl) {
    try {
        const parsed = new URL(scmUrl);
        return scmUrl.substring(scmUrl.indexOf(parsed.host) + parsed.host.length + 1);
    } catch (error) {
        return scmUrl;
    }
}

async function triggerSCAScan(inputs) {
    const { apiKey, repoUrl, branchName, thresholdCheck, thresholds, tag, asyncScan } = inputs;

    const strippedUrl = repoUrl.replace(/^https:\/\/[^@]+@/, 'https://');
    const appName = getAppNameFromUrl(strippedUrl);

    // URL-based SCA: the Sec1 backend resolves the repo itself, so no local
    // manifest file is uploaded and there is no package-manager restriction.
    const scanRequest = {
        location: strippedUrl,
        appName: appName,
        source: 'azure-ci',
        tag: tag
    };
    if (branchName) {
        scanRequest.branchName = branchName;
    }

    const requestPayload = { scanRequestList: [scanRequest] };

    const headers = {
        'sec1-api-key': apiKey,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    };

    console.log(`${boldText}Sec1 SCA Scan Config :${resetColor}`);
    console.log('SCM Url:   ', strippedUrl);
    console.log('Tag:       ', tag);
    console.log('Async Mode:', asyncScan ? 'Enabled (fire-and-forget)' : 'Disabled');
    console.log('Threshold: ', thresholdCheck ? 'Enabled' : 'Disabled');

    let triggerResponse;
    try {
        triggerResponse = await axios.post(scaApiUrl, requestPayload, { headers });
    } catch (error) {
        console.error("Error while triggering Sec1 SCA scan:", error.response?.data || error.message);
        return { status: 'FAILED', message: error.message };
    }

    const triggerBody = triggerResponse.data;
    if (!Array.isArray(triggerBody) || triggerBody.length === 0) {
        console.error(`${redCrossIcon} Error while processing Sec1 SCA scan result. No report id returned.`);
        return { status: 'FAILED', message: 'No report id returned from Sec1 SCA scan.' };
    }

    const reportId = triggerBody[0].uuid;
    const reportUrl = `${dashboardUrl}/dashboard-scan-details/${reportId}`;

    // Fire-and-forget: trigger the scan and return without waiting for results.
    if (asyncScan) {
        console.log('');
        console.log(`${boldText}Sec1 SCA Scan Result :${resetColor}`);
        console.log('Mode:       ASYNC (fire-and-forget)');
        console.log('Report URL: ', reportUrl);
        console.log('Status:     SUBMITTED');
        console.log(`${greenTickIcon}${greenColor} Sec1 SCA Scanner trigger completed${resetColor}`);
        return { status: 'SUCCESS', message: 'Sec1 SCA scan submitted', reportUrl, reportId };
    }

    // Synchronous: poll the status endpoint until the scan completes (or times out).
    return await pollScaStatus(reportId, reportUrl, apiKey, thresholdCheck, thresholds);
}

async function pollScaStatus(reportId, reportUrl, apiKey, thresholdCheck, thresholds) {
    const headers = {
        'sec1-api-key': apiKey,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    };

    const startTime = Date.now();
    let scanStatus = 'INITIATED';
    let responseJson = null;

    while (scanStatus.toUpperCase() !== 'COMPLETED') {
        if (Date.now() - startTime > SCA_POLL_MAX_DURATION_MS) {
            console.log('');
            console.log(`${boldText}Sec1 SCA Scan Result :${resetColor}`);
            console.log('Report URL: ', reportUrl);
            console.log('Status:     TIMED OUT');
            return { status: 'FAILED', message: 'Sec1 SCA Scan timed out after 30 minutes.' };
        }

        await sleep(SCA_POLL_INTERVAL_MS);

        let statusResponse;
        try {
            statusResponse = await axios.post(scaStatusUrl, [reportId], { headers });
        } catch (error) {
            console.error("Error while checking Sec1 SCA scan status:", error.response?.data || error.message);
            return { status: 'FAILED', message: error.message };
        }

        responseJson = statusResponse.data || {};
        const report = responseJson[reportId];
        if (!report || !report.status) {
            console.error(`${redCrossIcon} Error while processing Sec1 SCA scan result.`);
            return { status: 'FAILED', message: 'Error while processing Sec1 SCA scan result.' };
        }
        scanStatus = report.status;

        if (scanStatus.toUpperCase() === 'FAILED') {
            const scanResult = report.scannerResponseEntity || {};
            console.log('');
            console.log(`${boldText}Sec1 SCA Scan Result :${resetColor}`);
            console.log('Report URL: ', scanResult.reportUrl || reportUrl);
            console.log(`Status:${redColor} FAILURE${resetColor}`);
            console.log(`${redCrossIcon} ${boldText}${redColor}Sec1 SCA Security Scan Finished with failures.${resetColor}`);
            return { status: 'FAILED', message: 'Sec1 SCA Security Scan Finished with failures.' };
        }

        if (scanStatus.toUpperCase() !== 'COMPLETED') {
            console.log('Sec1 SCA Scan in progress...');
        }
    }

    const report = responseJson[reportId];
    const scanResult = report.scannerResponseEntity || {};

    if (scanResult.errorMessage) {
        console.error("Error while carrying out Sec1 SCA Security Scan: ", scanResult.errorMessage);
        return { status: 'FAILED', message: scanResult.errorMessage };
    }

    const cveCounts = scanResult.cveCountDetails || {};
    const summary = {
        critical: cveCounts.CRITICAL || 0,
        high: cveCounts.HIGH || 0,
        medium: cveCounts.MEDIUM || 0,
        low: cveCounts.LOW || 0
    };
    summary.totalCve = scanResult.totalCve || (summary.critical + summary.high + summary.medium + summary.low);
    summary.reportUrl = scanResult.reportUrl || reportUrl;

    console.log('');
    console.log(`${boldText}Sec1 SCA Scanner Report :${resetColor}`);
    console.log('Report URL: ', summary.reportUrl);
    console.log('Total Vulnerablities: ', summary.totalCve);
    console.log(`Vulnerability Details: ${redColor}Critical ${summary.critical}${resetColor} ${darkAmberColor}High ${summary.high}${resetColor} Medium ${summary.medium} Low ${summary.low}`);

    if (thresholdCheck && checkIfThresholdReached(summary, thresholds)) {
        return { status: 'FAILED', message: 'Vulnerabilities reported are more than threshold' };
    }

    console.log(`${greenTickIcon}${greenColor} Sec1 SCA Scanner Completed${resetColor}`);
    return { status: 'SUCCESS', message: 'Sec1 SCA Scan successfully finished' };
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function triggerSASTScan(inputs) {
    const { apiKey, repoUrl, branchName, thresholdCheck, thresholds } = inputs;
    const strippedUrl = repoUrl.replace(/^https:\/\/[^@]+@/, 'https://');

    // The SAST scan is asynchronous: /foss/sast/ascan triggers the scan and
    // returns a report uuid, then we poll /sast/asset/report/status until the
    // scan completes. This mirrors the SCA trigger/poll flow above.
    const scanRequest = {
        urlType: 'azure-scm',
        location: strippedUrl,
        branchName: branchName,
        source: 'azure-ci'
    };
    const requestPayload = {
        urlType: 'azure-scm',
        scanRequestList: [scanRequest]
    };

    const headers = {
        'sec1-api-key': apiKey,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    };

    console.log(`${boldText}Sec1 SAST Scan Config :${resetColor}`);
    console.log('SCM Url:   ', strippedUrl);
    console.log('Branch:    ', branchName || '(default)');
    console.log('Threshold: ', thresholdCheck ? 'Enabled' : 'Disabled');

    let triggerResponse;
    try {
        triggerResponse = await axios.post(sastApiUrl, requestPayload, { headers });
    } catch (error) {
        console.error("Error while triggering Sec1 SAST scan:", error.response?.data || error.message);
        return { status: 'FAILED', message: error.message };
    }

    const triggerBody = triggerResponse.data;
    if (!Array.isArray(triggerBody) || triggerBody.length === 0 || !triggerBody[0].uuid) {
        console.error(`${redCrossIcon} Error while processing Sec1 SAST scan result. No report id returned.`);
        return { status: 'FAILED', message: 'No report id returned from Sec1 SAST scan.' };
    }

    const reportId = triggerBody[0].uuid;
    const reportUrl = `${dashboardUrl}/sast-advance-dashboard/${reportId}`;

    return await pollSastStatus(reportId, reportUrl, apiKey, thresholdCheck, thresholds);
}

async function pollSastStatus(reportId, reportUrl, apiKey, thresholdCheck, thresholds) {
    const headers = {
        'sec1-api-key': apiKey,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    };

    const startTime = Date.now();
    let scanStatus = 'INITIATED';
    let report = null;

    while (scanStatus.toUpperCase() !== 'COMPLETED') {
        if (Date.now() - startTime > SAST_POLL_MAX_DURATION_MS) {
            console.log('');
            console.log(`${boldText}Sec1 SAST Scan Result :${resetColor}`);
            console.log('Report URL: ', reportUrl);
            console.log('Status:     TIMED OUT');
            return { status: 'FAILED', message: 'Sec1 SAST Scan timed out after 30 minutes.' };
        }

        await sleep(SAST_POLL_INTERVAL_MS);

        let statusResponse;
        try {
            statusResponse = await axios.post(sastStatusUrl, { reportId: [reportId] }, { headers });
        } catch (error) {
            console.error("Error while checking Sec1 SAST scan status:", error.response?.data || error.message);
            return { status: 'FAILED', message: error.message };
        }

        // The status endpoint returns an array of report entries; find ours.
        const statusBody = Array.isArray(statusResponse.data) ? statusResponse.data : [];
        report = statusBody.find((entry) => entry.reportId === reportId) || statusBody[0];
        if (!report || !report.scanStatus) {
            console.error(`${redCrossIcon} Error while processing Sec1 SAST scan result.`);
            return { status: 'FAILED', message: 'Error while processing Sec1 SAST scan result.' };
        }
        scanStatus = report.scanStatus;

        if (report.errorMessage) {
            console.error("Error while carrying out Sec1 SAST Security Scan: ", report.errorMessage);
            return { status: 'FAILED', message: report.errorMessage };
        }

        if (scanStatus.toUpperCase() === 'FAILED') {
            console.log('');
            console.log(`${boldText}Sec1 SAST Security Scanner Report :${resetColor}`);
            console.log('Report URL: ', reportUrl);
            console.log(`Status:${redColor} FAILURE${resetColor}`);
            console.log(`${redCrossIcon} ${boldText}${redColor}Sec1 SAST Security Scan Finished with failures.${resetColor}`);
            return { status: 'FAILED', message: 'Sec1 SAST Security Scan Finished with failures.' };
        }

        if (scanStatus.toUpperCase() !== 'COMPLETED') {
            console.log('Sec1 SAST Scan in progress...');
        }
    }

    const summary = {
        critical: report.critical || 0,
        high: report.high || 0,
        medium: report.medium || 0,
        low: report.low || 0
    };
    summary.totalCve = report.total || (summary.critical + summary.high + summary.medium + summary.low);
    summary.reportUrl = reportUrl;

    console.log('');
    console.log(`${boldText}Sec1 SAST Scanner Report :${resetColor}`);
    console.log('Report URL: ', summary.reportUrl);
    console.log('Total Vulnerablities: ', summary.totalCve);
    console.log(`Vulnerability Details: ${redColor}Critical ${summary.critical}${resetColor} ${darkAmberColor}High ${summary.high}${resetColor} Medium ${summary.medium} Low ${summary.low}`);

    if (thresholdCheck && checkIfThresholdReached(summary, thresholds)) {
        return { status: 'FAILED', message: 'Vulnerabilities reported are more than threshold' };
    }

    console.log(`${greenTickIcon}${greenColor} Sec1 SAST Scanner Completed${resetColor}`);
    return { status: 'SUCCESS', message: 'Sec1 SAST Scan successfully finished' };
}

async function triggerDASTScan(inputs) {
    const { apiKey, dastTargetUrl, dastScanType } = inputs;

    const requestPayload = {
        targetUrl: dastTargetUrl,
        applicationName: dastTargetUrl,
        scanType: dastScanType
    };

    const headers = {
        'sec1-api-key': apiKey,
        'Content-Type': 'application/json',
    };

    let response;
    try {
        response = await axios.post(dastApiUrl, requestPayload, { headers });
    } catch (error) {
        const apiMessage = error.response && error.response.data && (error.response.data.errorMessage || error.response.data.message);
        console.error(`${redCrossIcon} Error while triggering Sec1 DAST scan: ${apiMessage || error.message}`);
        return { status: 'FAILED', message: apiMessage || error.message };
    }

    const responseObject = response.data || {};

    if (responseObject.errorMessage) {
        console.error(`${redCrossIcon} Error while triggering Sec1 DAST scan: ${responseObject.errorMessage}`);
        return { status: 'FAILED', message: responseObject.errorMessage };
    }

    const { scanId, url: dashboardUrl } = responseObject;

    console.log('');
    console.log(`${boldText}Sec1 DAST Scan Triggered :${resetColor}`);
    console.log(`Target URL: ${dastTargetUrl}`);
    console.log(`Scan Type: ${dastScanType}`);
    if (scanId) {
        console.log(`Scan ID: ${scanId}`);
    }
    if (dashboardUrl) {
        console.log(`Dashboard URL: ${dashboardUrl}`);
    } else {
        console.log(`${darkAmberColor}Dashboard URL was not returned by the API. Check the Sec1 portal for scan progress.${resetColor}`);
    }

    console.log(`${infoIcon} DAST scan is running asynchronously. Monitor progress at the dashboard URL above.`);
    console.log(`${greenTickIcon}${greenColor} Sec1 DAST Scanner trigger completed${resetColor}`);
    return { status: 'SUCCESS', message: 'Sec1 DAST scan triggered', dashboardUrl, scanId };
}

async function triggerApiSecurityScan(inputs) {
    const { apiKey, apiSecurityConfigId } = inputs;

    // API Security is triggered by a pre-created config id from the Sec1 portal.
    // Like DAST, it is fire-and-forget: we trigger the scan and return without
    // waiting for results (no threshold gate applies).
    const requestPayload = {
        configId: apiSecurityConfigId
    };

    const headers = {
        'sec1-api-key': apiKey,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    };

    let response;
    try {
        response = await axios.post(apiSecurityApiUrl, requestPayload, { headers });
    } catch (error) {
        const apiMessage = error.response && error.response.data && (error.response.data.errorMessage || error.response.data.message);
        console.error(`${redCrossIcon} Error while triggering Sec1 API Security scan: ${apiMessage || error.message}`);
        return { status: 'FAILED', message: apiMessage || error.message };
    }

    const responseObject = response.data || {};

    if (responseObject.errorMessage) {
        console.error(`${redCrossIcon} Error while triggering Sec1 API Security scan: ${responseObject.errorMessage}`);
        return { status: 'FAILED', message: responseObject.errorMessage };
    }

    const { scanId, url: dashboardUrl } = responseObject;

    console.log('');
    console.log(`${boldText}Sec1 API Security Scan Triggered :${resetColor}`);
    console.log(`Config ID: ${apiSecurityConfigId}`);
    if (scanId) {
        console.log(`Scan ID: ${scanId}`);
    }
    if (dashboardUrl) {
        console.log(`Dashboard URL: ${dashboardUrl}`);
    } else {
        console.log(`${darkAmberColor}Dashboard URL was not returned by the API. Check the Sec1 portal for scan progress.${resetColor}`);
    }

    console.log(`${infoIcon} API Security scan is running asynchronously. Monitor progress at the dashboard URL above.`);
    console.log(`${greenTickIcon}${greenColor} Sec1 API Security Scanner trigger completed${resetColor}`);
    return { status: 'SUCCESS', message: 'Sec1 API Security scan triggered', dashboardUrl, scanId };
}

function checkIfThresholdReached(summary, thresholds) {
    let thresholdBreak = false;
    Object.entries(thresholds).forEach(([severity, value]) => {
        // Skip blank thresholds (left empty in the UI). Only a configured,
        // numeric threshold can break the build, and only when there is at
        // least one finding at that severity.
        if (value === undefined || value === '') {
            return;
        }
        if (summary[severity] !== 0 && summary[severity] >= value) {
            thresholdBreak = true;
        }
    });

    if (thresholdBreak) {
        console.log(`${boldText}${redColor}Build failed because of threshold breach.${resetColor}`);
    }

    return thresholdBreak;
}

//If it is blank then return blank otherwise perform validation for integer
function validateThreshold(value) {
    if (value === undefined || value === '') {
        return value; // Allow blank value
    }
    const numericRegex = /^[0-9]+$/;
    if (!numericRegex.test(value)) {
        throw new Error('Threshold value must be a non-negative integer or blank.');
    }

    return parseInt(value, 10);
}

// Run the task
run();

const tl = require('azure-pipelines-task-lib/task');
const axios = require('axios');
const fs = require('fs');
const FormData = require('form-data');
const path = require('path');

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

const apiUrl = 'https://api.sec1.io/foss/scan/file'; // Replace with your actual API endpoint
const sastApiUrl = 'https://api.sec1.io/foss/sast/scan'; // Replace with your actual API endpoint


async function run() {
    try {
        console.log(`${startIcon} ${boldText}Sec1 Security Scanner Started ...${resetColor}`);

        // Final results processing
        let finalResult = tl.TaskResult.Succeeded;
        let resultMessage = 'Sec1 Security Scanner task completed successfully';
        let scaPassed = true
        let sastPassed = true

        //Read all input and carry out validation
        const inputs = await readInputs();
        if (inputs.enableSCA) {
            console.log(`${startIcon}${startIcon} Initiating Sec1 SCA Scanner ...${resetColor}`);
            //Trigger SCA Scan
            const scaResults = await triggerSCAScan(inputs);
            if (scaResults && scaResults.status === 'FAILED') {
                scaPassed = false
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
        if (!scaPassed && !sastPassed) {
            resultMessage = 'Both Sec1 SCA & SAST Scan failed';
        } else if (!scaPassed) {
            resultMessage = 'Sec1 SCA Scan failed';
        } else if(!sastPassed) {
            resultMessage = 'Sec1 SAST Scan failed';
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
    if (!enableSCA && !enableSAST) {
        throw new Error('At least one scan type (SCA or SAST) must be enabled.');
    }

    const apiKey = getServiceConnectionPassword(serviceConnectionId);

    const repoUrl = tl.getVariable('Build.Repository.Uri');
    const fullBranchName = tl.getVariable('Build.SourceBranch');
    const branchName = fullBranchName.replace('refs/heads/', '');

    const selectedFilePath = getSelectedPath();

    const thresholdCheckInput = tl.getInput('thresholdCheck', true) || 'false';
    const thresholdCheck = thresholdCheckInput.toLowerCase() === 'true';

    const critical = validateThreshold(tl.getInput('critical'));
    const high = validateThreshold(tl.getInput('high'));
    const medium = validateThreshold(tl.getInput('medium'));
    const low = validateThreshold(tl.getInput('low'));

    return { apiKey, repoUrl, branchName, selectedFilePath, thresholdCheck, thresholds: { critical, high, medium, low }, enableSCA, enableSAST};
}

function getServiceConnectionPassword(serviceConnectionId) {
    const serviceConnection = tl.getEndpointAuthorization(serviceConnectionId, false);
    if (!serviceConnection) {
        throw new Error('Service connection not found or authorization details missing.');
    }
    return serviceConnection.parameters['password'];
}

function getSelectedPath() {
    let filePath = tl.getInput('packagePath') || '';
    filePath = filePath.trim();

    let selectedFilePath;

    //File path is not blank or file path is not equal to current directory which means it should look up for pom.xml directly.
    if (filePath !== '' && filePath !== process.cwd() && checkFilePresence(filePath)) {
        selectedFilePath = filePath;
    } else if (checkFilePresence('pom.xml')) {
        // If `filePath` is blank, check for the presence of 'pom.xml'
        selectedFilePath = 'pom.xml';
    } else if (checkFilePresence('package.json')) {
        // If 'pom.xml' is not present, check for the presence of 'package.json'
        selectedFilePath = 'package.json';
    } else {
        // If neither 'pom.xml' nor 'package.json' is present
        throw new Error('Repo not supported. Supported Repos are Maven and NodeJS repo');
    }
    console.log('Selected File for Sec1 SCA Scanner :', selectedFilePath);
    return selectedFilePath;
}

async function triggerSCAScan(inputs) {
    const { apiKey, repoUrl, branchName, selectedFilePath, thresholdCheck, thresholds } = inputs;

    const strippedUrl = repoUrl.replace(/^https:\/\/[^@]+@/, 'https://');
    const moduleName = path.relative(process.cwd(), selectedFilePath);

    // Request parameters
    const requestJson = {
        source: 'azure-ci',
        location: strippedUrl,
        moduleName: moduleName,
        branch: branchName
    };

    // Set headers
    const headers = {
        'sec1-api-key': apiKey,
        'Content-Type': 'multipart/form-data', // Ensure proper content type for multipart form data
    };

    // Create form data
    const formData = new FormData();
    formData.append('file', fs.createReadStream(selectedFilePath));
    formData.append('request', JSON.stringify(requestJson));

    scanRequest(apiUrl, apiKey, formData).then((res) => {
        let responseObject = res.data
        let summary = {};
        if (responseObject.errorMessage != undefined && responseObject.errorMessage != '') {
            console.error("Error while carrying out Sec1 Security Scan: ", responseObject.errorMessage);
            return { status: 'FAILED', message: responseObject.errorMessage };
        } else if (responseObject.status == "FAILED") {
            console.log(`${boldText}Sec1 SCA Scanner Report :${resetColor}`);
            console.log('Report ID:', responseObject.reportId);
            console.log('Report URL:', responseObject.reportUrl);
            console.log(`Status:${redColor} FAILURE${resetColor}`);
            console.log(`${redCrossIcon} ${boldText}${redColor}Sec1 Security Scan Finished with failures.${resetColor}`);
            return { status: 'FAILED', message: 'Sec1 SCA Security Scan Finished with failures.' };
        } else {
            summary.critical = responseObject.cveCountDetails.CRITICAL || 0;
            summary.high = responseObject.cveCountDetails.HIGH || 0;
            summary.medium = responseObject.cveCountDetails.MEDIUM || 0;
            summary.low = responseObject.cveCountDetails.LOW || 0;
            summary.totalCve = responseObject.totalCve || 0;
            summary.reportUrl = responseObject.reportUrl;
            console.log('');
            console.log(`${boldText}Sec1 SCA Scanner Report :${resetColor}`);
            console.log('Report URL: ', summary.reportUrl);
            console.log('Total Vulnerablities: ', summary.totalCve);
            // Print na field only if it's not zero
            if (summary.na !== undefined && summary.na !== 0) {
                console.log(`Vulnerability Details: ${redColor}Critical ${summary.critical}${resetColor} ${darkAmberColor}High ${summary.high}${resetColor} Medium ${summary.medium} Low ${summary.low} NA ${summary.na}`);
            } else {
                console.log(`Vulnerability Details: ${redColor}Critical ${summary.critical}${resetColor} ${darkAmberColor}High ${summary.high}${resetColor} Medium ${summary.medium} Low ${summary.low}`);
            }

            if (thresholdCheck) {
                if (checkIfThresholdReached(summary, thresholds)) {
                    throw new Error("Vulnerabilities reported are more than threshold");
                }
            }
            console.log(`${greenTickIcon}${greenColor} Sec1 SCA Scanner Completed${resetColor}`);
            return { status: 'SUCCESS', message: 'Sec1 SCA Scan successfully finished' };
        }
    }).catch((error) => {
        console.error("Error while executing Sec1 Container Security scan:", error.response && error.response.data);
        return { status: 'FAILED', message: error.message };
    });
}

function scanRequest(apiEndpoint, apiKey, formData) {
    return axios.post(apiEndpoint, formData,
        {
            headers: {
                'Content-Type': 'multipart/form-data',
                'sec1-api-key': apiKey
            }
        })
}

async function triggerSASTScan(inputs) {
    const { apiKey, repoUrl, branchName, thresholdCheck, thresholds} = inputs;
    const strippedUrl = repoUrl.replace(/^https:\/\/[^@]+@/, 'https://');

    // Request parameters
    const requestPayload = {
        urlType: "azure-scm",
        location: strippedUrl,
        branchName: branchName
    };

    // Set headers
    const headers = {
        'sec1-api-key': apiKey,
        'Content-Type': 'application/json',
    };

    try {
        const response = await axios.post(sastApiUrl, requestPayload, { headers });
        const responseObject = response.data;
        let summary = {};

        if (responseObject.errorMessage != undefined && responseObject.errorMessage != '') {
            console.error("Error while carrying out Sec1 SAST Security Scan: ", responseObject.errorMessage);
            return { status: 'FAILED', message: responseObject.errorMessage };
        } else if (responseObject.status == "FAILED") {
            console.log(`${boldText}Sec1 SAST Security Scanner Report :${resetColor}`);
            console.log('Report ID:', responseObject.reportId);
            console.log('Report URL:', responseObject.reportUrl);
            console.log(`Status:${redColor} FAILURE${resetColor}`);
            console.log(`${redCrossIcon} ${boldText}${redColor}Sec1 SAST Security Scan Finished with failures.${resetColor}`);
            return { status: 'FAILED', message: 'Sec1 SAST Security Scan Finished with failures.' };
        } else {
            summary.critical = responseObject.cveCountDetails.CRITICAL || 0;
            summary.high = responseObject.cveCountDetails.HIGH || 0;
            summary.medium = responseObject.cveCountDetails.MEDIUM || 0;
            summary.low = responseObject.cveCountDetails.LOW || 0;
            summary.totalCve = responseObject.totalCve || 0;
            summary.reportUrl = responseObject.reportUrl;
            console.log('');
            console.log(`${boldText}Sec1 SAST Scanner Report :${resetColor}`);
            console.log('Report URL: ', summary.reportUrl);
            console.log('Total Vulnerablities: ', summary.totalCve);
            console.log(`Vulnerability Details: ${redColor}Critical ${summary.critical}${resetColor} ${darkAmberColor}High ${summary.high}${resetColor} Medium ${summary.medium} Low ${summary.low}`);

            if (thresholdCheck) {
                if (checkIfThresholdReached(summary, thresholds)) {
                    throw new Error("Vulnerabilities reported are more than threshold");
                }
            }
            console.log(`${greenTickIcon}${greenColor} Sec1 SAST Scanner Completed${resetColor}`);
            return { status: 'SUCCESS', message: 'Sec1 SAST Scan successfully finished' };
        }        
    } catch (error) {
        console.error("Error while executing Sec1 SAST scan:", error.response?.data || error.message);
        return { status: 'FAILED', message: error.message };
    }
}

function checkFilePresence(filePath) {
    try {
        fs.accessSync(filePath, fs.constants.F_OK);
        return true;
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.log(`File '${filePath}' does not exist.`);
            return false;
        } else {
            // Handle other errors
            console.error(`Error checking file existence: ${error.message}`);
            return false;
        }
    }
}

function checkIfThresholdReached(summary, thresholds) {
    let thresholdBreak = false;
    Object.entries(thresholds).forEach(([severity, value]) => {
        if (summary[severity] >= value) {
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

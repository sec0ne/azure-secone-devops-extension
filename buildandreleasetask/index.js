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


function run() {
  try {
    console.log('Sec1 SCA Scanner Started ...');
    const serviceConnectionId = tl.getInput('serviceConnection', true) || '';
   
    if (!serviceConnectionId) {
        throw new Error('Service connection not found or authorization details missing.');
    }

    const serviceConnection = tl.getEndpointAuthorization(serviceConnectionId, false);
    if (!serviceConnection) {
        throw new Error('Service connection not found or authorization details missing.');
    }

    const repoUrl = getRepositoryUrl();
    
    const apiKey = serviceConnection.parameters['password'];
    const apiUrl = 'https://api.sec1.io/rest/foss'; // Replace with your actual API endpoint
    
    const selectedFilePath = getSelectedPath();

    triggerSec1Scan(apiUrl, apiKey, selectedFilePath, repoUrl);
    // Set the task result
    tl.setResult(tl.TaskResult.Succeeded, 'Task completed successfully');

  } catch (err) {
    // Handle errors and set the task result accordingly
    tl.setResult(tl.TaskResult.Failed, err.message);
  }
}

function getRepositoryUrl() {
    const repoUrl = tl.getVariable('Build.Repository.Uri');
    return repoUrl;
}

function getSelectedPath() {
    let filePath = tl.getInput('packagePath') || '';
    filePath = filePath.trim();

    let selectedFilePath;

    //File path is not blank or file path is not equal to current directory which means it should look up for pom.xml directly.
    if (filePath !== '' && filePath !== process.cwd() && checkFilePresence(filePath) ) {
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
    console.log('Selected File for Sec1 Scanner :', selectedFilePath);
    return selectedFilePath;
}

async function triggerSec1Scan(apiUrl, apiKey, filePath, repoUrl) {
    // API endpoint URL
    const url = apiUrl;

    const strippedUrl = repoUrl.replace(/^https:\/\/[^@]+@/, 'https://');
  
    // Request parameters
    const requestJson = {
        source: 'azure-ci',
        location: strippedUrl
    };

    // Set headers
    const headers = {
      'sec1-api-key': apiKey,
      'Content-Type': 'multipart/form-data', // Ensure proper content type for multipart form data
    };
  
    // Create form data
    const formData = new FormData();
    formData.append('file', fs.createReadStream(filePath));
    formData.append('request', JSON.stringify(requestJson));

    scanRequest(apiUrl, apiKey, formData).then((res) => {
        let responseObject = res.data
        let summary = {};
        if (responseObject.errorMessage != undefined && responseObject.errorMessage != '') {
            console.error("Error while carrying out Sec1 SCA Scan: ", responseObject.errorMessage);
            tl.setResult(tl.TaskResult.Failed, responseObject.errorMessag);
        } else if(responseObject.status == "FAILED" ){
            console.log('Sec1 Container Image Scanner Report :');
            console.log('Report ID:', responseObject.reportId);
            console.log('Report URL:', responseObject.reportUrl);
            console.log(`Status:${redColor} FAILURE${resetColor}`);
            tl.setResult(tl.TaskResult.Failed, responseObject.errorMessag);
        } else {
            summary.critical = responseObject.cveCountDetails.CRITICAL || 0;
            summary.high = responseObject.cveCountDetails.HIGH || 0;
            summary.medium = responseObject.cveCountDetails.MEDIUM || 0;
            summary.low = responseObject.cveCountDetails.LOW || 0;
            summary.totalCve = responseObject.totalCve || 0;
            summary.reportUrl = responseObject.reportUrl;
            console.log('');
            console.log('Sec1 SCA Scanner Report:');
            console.log('Report URL: ', summary.reportUrl);
            console.log('Total Vulnerablities: ', summary.totalCve);
            console.log(`Vulnerability Details:  ${redColor}Critical: ${summary.critical}${resetColor}, ${darkAmberColor}High: ${summary.high}${resetColor}, Medium: ${summary.medium}, Low: ${summary.low}`);

            var thresholdCheckInput = tl.getInput('thresholdCheck', true) || 'false';
            const thresholdCheck = thresholdCheckInput.toLowerCase() === 'true';
            if (thresholdCheck) {
                var thresholdMap = getThresholdMap();
                if (thresholdMap.size > 0 && checkIfThresholdReached(summary, thresholdMap)) {
                    tl.setResult(tl.TaskResult.Failed, "Vulnerabilities reported are more than threshold");
                }
            }
        }
    }).catch((e) => {
        if(e.response && e.response.data && e.response.data.errorMessage){
            printErrorResponse(options, e.response.data.errorMessage);
        }
        tl.setResult(tl.TaskResult.Failed, e);
        if (e.response.data) {
            console.log("Error while executing Sec1 Security scan : ", e.response.data);
        }
    });
  }

  function scanRequest(apiEndpoint, apiKey, formData) {
    return axios.post(apiEndpoint + "/scan/file", formData,
        {
            headers: {
                'Content-Type': 'multipart/form-data',
                'sec1-api-key': apiKey
            }
        })
}

function printErrorResponse(options, err) {
    console.log("=====================Scan Summary=====================");
    console.log(`Scan file : ` + chalk.black.bold(`${options.file}`), );
    if (err != undefined && err != '') {
        console.log(chalk.red.bold(err));
    }
    console.log(chalk.red.bold("Error occurred while scanning. Please check the scanned manifest"))
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

  function getThresholdMap() {
    const critical = tl.getInput('critical');
    const high = tl.getInput('high');
    const medium = tl.getInput('medium');
    const low = tl.getInput('low');

    let data = new Map();
    if (!isNaN(critical)) {
        data.set('critical', critical);
    }
    if (!isNaN(high)) {
        data.set('high', high);
    }
    if (!isNaN(medium)) {
        data.set('medium', medium);
    }
    if (!isNaN(low)) {
        data.set('low', low);
    }
    return data;
}

function checkIfThresholdReached(summary, thresholdMap) {
    let thresholdBreak = false;
    thresholdMap.forEach((value, severity) => {
        if (summary[severity] >= value) {
            thresholdBreak = true
        }
    })

    // Determine the color based on the value of thresholdBreak
    const color = thresholdBreak ? redColor : greenColor;

    // Print the boolean value in upper case with the appended string in the determined color
    console.log(`\nThreshold Break:${color} ${String(thresholdBreak).toUpperCase()}${resetColor}`);

    return thresholdBreak;
}

// Run the task
run();

const tl = require('azure-pipelines-task-lib/task');
const axios = require('axios');
const fs = require('fs');
const FormData = require('form-data');


function run() {
  try {
    
    const serviceConnectionId = tl.getInput('serviceConnection', true) || '';
   
    if (!serviceConnectionId) {
        throw new Error('Service connection not found or authorization details missing.');
    }

    const serviceConnection = tl.getEndpointAuthorization(serviceConnectionId, false);
    if (!serviceConnection) {
        throw new Error('Service connection not found or authorization details missing.');
    }

    const apiKey = serviceConnection.parameters['password'];
    const apiUrl = 'https://api.sec1.io/rest/foss'; // Replace with your actual API endpoint
    var filePath;
    if(checkFilePresence('pom.xml')) {
        filePath = 'pom.xml';
    } else if(checkFilePresence('package.json')) {
        filePath = '/Users/dineshrawat/Desktop/TestWorkspace/vulnerable-node/package.json';
    } else {
        throw new Error('Repo not supported. Supported Repos are Maven and NodeJS repo');
    }

    console.log("File Path : ", filePath);

    triggerSec1Scan(apiUrl, apiKey, filePath);
    // Set the task result
    tl.setResult(tl.TaskResult.Succeeded, 'Task completed successfully');

  } catch (err) {
    // Handle errors and set the task result accordingly
    tl.setResult(tl.TaskResult.Failed, err.message);
  }
}

async function triggerSec1Scan(apiUrl, apiKey, filePath) {
    // API endpoint URL
    const url = apiUrl;
  
    // Request parameters
    const requestJson = {
        source: 'cli'
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
        let responseObject = res.data.body
        let summary = {};
        summary.scanFile = filePath;
        if (responseObject.errorMessage != undefined && responseObject.errorMessage != '') {
            printErrorResponse(options, responseObject.errorMessage);
            tl.setResult(tl.TaskResult.Failed, responseObject.errorMessag);
        } else if(responseObject.status == "FAILED" ){
            options.file = summary.scanFile
            printErrorResponse(options, "Scan failed for report : " + responseObject.reportId);
            tl.setResult(tl.TaskResult.Failed, responseObject.errorMessag);
        } else {
            summary.critical = responseObject.cveCountDetails.CRITICAL || 0;
            summary.high = responseObject.cveCountDetails.HIGH || 0;
            summary.medium = responseObject.cveCountDetails.MEDIUM || 0;
            summary.low = responseObject.cveCountDetails.LOW || 0;
            summary.totalCve = responseObject.totalCve || 0;
            summary.reportUrl = responseObject.reportUrl;
            console.log('Critical Vulnerability :', summary.critical);
            console.log('High Vulnerability :', summary.high);
            console.log('Medium Vulnerability :', summary.medium);
            console.log('Low Vulnerability :', summary.low);
            console.log('Total CVE Vulnerability :', summary.totalCve);
            console.log('Report URL :', summary.reportUrl);

            var thresholdCheckInput = tl.getInput('thresholdCheck', true) || 'false';
            //var thresholdCheckInput = 'true';
            const thresholdCheck = thresholdCheckInput.toLowerCase() === 'true';
            var thresholdMap = getThresholdMap();
            if (thresholdCheck && thresholdMap.size > 0 && checkIfThresholdReached(summary, thresholdMap)) {
                console.error('Vulnerabilities reported are more than threshold.');
                tl.setResult(tl.TaskResult.Failed, "Vulnerabilities reported are more than threshold");
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
    const critical = tl.getInput('critical', true) || '1';
    const high = tl.getInput('high', true) || '0';
    const medium = tl.getInput('medium', true) || '0';
    const low = tl.getInput('low', true) || '0';

    let data = new Map();
    if (!isNaN(critical)) {
        data.set('critical', critical);
    }
    if (!isNaN(critical)) {
        data.set('high', high);
    }
    if (!isNaN(critical)) {
        data.set('medium', medium);
    }
    if (!isNaN(critical)) {
        data.set('low', low);
    }
    console.log("Threshold Values : ", data);
    return data;
}

function checkIfThresholdReached(summary, thresholdMap) {
    let thresholdBreak = false;
    thresholdMap.forEach((value, severity) => {
        if (summary[severity] >= value) {
            thresholdBreak = true
        }
    })
    console.log("Threshold Break : ", thresholdBreak)
    return thresholdBreak;
}

// Run the task
run();

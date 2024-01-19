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
    const filePath = 'pom.xml'; // Replace with the actual file path

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
        } else if(responseObject.status == "FAILED" ){
            options.file = summary.scanFile
            printErrorResponse(options, "Scan failed for report : " + responseObject.reportId);
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
        }
    }).catch((e) => {
        if(e.response && e.response.data && e.response.data.errorMessage){
            printErrorResponse(options, e.response.data.errorMessage);
        }
        console.log(e);
    });
  }

  function scanRequest(apiEndpoint, apiKey, formData) {
    //console.log("Start scanning from file")
    //const fullRepoUrl = "https://github.com/sdthatte/test-scan";
    return axios.post(apiEndpoint + "/scan/file", formData,
        {
            headers: {
                'Content-Type': 'multipart/form-data',
                'sec1-api-key': apiKey
            }
        })
}

function printErrorResponse(options, err) {
    console.log("=====================Scan Summary=====================")
    
    if (options.system == "cli") {
        console.log(`Scan file : ` + chalk.black.bold(`${options.file}`), );
        if (err != undefined && err != '') {
            console.log(chalk.red.bold(err));
        }
        console.log(chalk.red.bold("Error occurred while scanning. Please check the scanned manifest"))
    } else if (options.system == "gitaction") {
        if (err != undefined && err != '') {
            core.error(err);
        }
        core.setFailed("Error occurred while scanning. Please check git action configuration")
    }
}

// Run the task
run();

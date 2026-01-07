const tl = require('azure-pipelines-task-lib/task');
const { exec } = require('child_process');
const util = require('util');


/**
 * Execute command with timeout support
 */
async function execWithTimeout(command, options = {}) {
    const timeout = options.timeout || 60000; // Default 1 minute timeout
    
    console.log(`🔧 Executing: ${command}`);
    
    return new Promise((resolve, reject) => {
        const child = exec(command, options, (error, stdout, stderr) => {
            if (error) {
                reject(error);
            } else {
                resolve({ stdout, stderr });
            }
        });
        
        // Set timeout
        const timer = setTimeout(() => {
            child.kill('SIGKILL');
            reject(new Error(`Command timed out after ${timeout}ms: ${command}`));
        }, timeout);
        
        child.on('exit', () => {
            clearTimeout(timer);
        });
    });
}

/**
 * Deploy application based on deployment type
 */
async function deployApplication() {
    const deploymentType = tl.getInput('deploymentType', true);
    
    console.log(`🚀 Starting deployment with type: ${deploymentType}`);
    
    try {
        if (deploymentType === 'docker') {
            const imageName = await buildDockerImage();
            return await deployDockerToGcpVm(imageName);
        } else if (deploymentType === 'script') {
            return await deployViaScript();
        } else {
            throw new Error(`Unsupported deployment type: ${deploymentType}. Only 'docker' and 'script' are supported.`);
        }
    } catch (error) {
        console.error(`❌ Deployment failed: ${error.message}`);
        throw error;
    }
}

/**
 * Build Docker image
 */
async function buildDockerImage() {
    const buildId = tl.getVariable('Build.BuildId') || Date.now().toString();
    const imageName = `sec1-app:${buildId}`;
    
    console.log(`🔨 Building Docker image: ${imageName}`);
    
    try {
        await execWithTimeout(`docker build -t ${imageName} .`, { timeout: 300000 });
        console.log('✅ Docker image built successfully');
        return imageName;
    } catch (error) {
        console.error('❌ Docker build failed:');
        throw error;
    }
}

/**
 * Deploy Docker image to GCP VM using external script
 */
async function deployDockerToGcpVm(imageName) {
    const gcpProject = tl.getInput('gcpProjectId', true);
    const gcpZone = tl.getInput('gcpZone', true);
    const gcpVmName = tl.getInput('gcpVmName', true);
    
    console.log(`🌩️ Deploying Docker image to GCP VM: ${gcpVmName}`);
    
    const artifactRegistry = `us-central1-docker.pkg.dev/${gcpProject}/sec1-public-repo/${imageName}`;
    
    try {
        console.log(`🏷️ Tagging and pushing image...`);
        await execWithTimeout(`docker tag ${imageName} ${artifactRegistry}`);
        await execWithTimeout(`gcloud auth configure-docker us-central1-docker.pkg.dev --quiet`, { timeout: 30000 });
        await execWithTimeout(`docker push ${artifactRegistry}`, { timeout: 300000 });
        
        console.log(`🚀 Executing Docker deployment script on VM (files should already be copied by pipeline)...`);
        await execWithTimeout(`gcloud compute ssh ${gcpVmName} --zone=${gcpZone} --command="cd /opt/sec1-app && sudo ./docker-deployment.sh ${artifactRegistry}"`, { timeout: 300000 });
        
        const { stdout } = await execWithTimeout(`gcloud compute instances describe ${gcpVmName} --zone=${gcpZone} --format='get(networkInterfaces[0].accessConfigs[0].natIP)'`);
        const externalIp = stdout.trim();
        const applicationUrl = `http://${externalIp}:8000`;
        
        console.log(`✅ Docker deployment completed! Application URL: ${applicationUrl}`);
        return { applicationUrl };
        
    } catch (error) {
        console.error('❌ Docker deployment failed:', error.message);
        throw error;
    }
}

/**
 * Deploy via script - copies app.py and runs Python application using external script
 */
async function deployViaScript() {
    const gcpZone = tl.getInput('gcpZone', true);
    const gcpVmName = tl.getInput('gcpVmName', true);
    
    console.log(`📜 Deploying Python app via script to VM: ${gcpVmName}`);
    
    try {
        console.log(`🚀 Executing application deployment script on VM (files should already be copied by pipeline)...`);
        await execWithTimeout(`gcloud compute ssh ${gcpVmName} --zone=${gcpZone} --command="cd /opt/sec1-app && sudo ./app-deployment.sh"`, { timeout: 300000 });
        
        const { stdout } = await execWithTimeout(`gcloud compute instances describe ${gcpVmName} --zone=${gcpZone} --format='get(networkInterfaces[0].accessConfigs[0].natIP)'`);
        const externalIp = stdout.trim();
        const applicationUrl = `http://${externalIp}:8000`;
        
        console.log(`✅ Script deployment completed! Application URL: ${applicationUrl}`);
        return { applicationUrl };
        
    } catch (error) {
        console.error('❌ Script deployment failed:', error.message);
        throw error;
    }
}

module.exports = {
    deployApplication
};
# Build, Package, and Test Sec1 Security Azure DevOps Extension

This guide explains how to build, package, and test the Sec1 Security extension in Azure DevOps.

## Prerequisites

- Node.js (v16+ recommended)
- npm (v8+ recommended)
- [tfx-cli](https://github.com/microsoft/tfs-cli) (`npm install -g tfx-cli`)
- Azure DevOps organization with permissions to install extensions
- Valid Sec1 API key from [Scopy](https://unified.sec1.io/)

---

## 1. Install Dependencies

Navigate to the `buildandreleasetask` directory and install dependencies:

```sh
cd buildandreleasetask
npm install
```

---

## 2. Build the Extension (Optional)

If you make changes to TypeScript files, compile them using the [tsconfig.json](buildandreleasetask/tsconfig.json):

```sh
cd buildandreleasetask
npx tsc
```

> **Note:** The current implementation uses JavaScript ([index.js](buildandreleasetask/index.js)), so this step is optional unless you're converting to TypeScript.

---

## 3. Package the Extension

Use `tfx-cli` to package the extension using the [vss-extension.json](vss-extension.json) manifest:

```sh
tfx extension create --manifest-globs vss-extension.json
```

This will generate a `.vsix` file (e.g., `Sec1.build-release-task-1.2.1.vsix`) in your workspace.

---

## 4. Publish to Azure DevOps Marketplace

### Option A: Upload via Web Interface
1. Go to [Visual Studio Marketplace Manage page](https://marketplace.visualstudio.com/manage)
2. Click "New extension" > "Azure DevOps"
3. Upload the `.vsix` file

### Option B: Command Line Publishing
```sh
tfx extension publish --manifest-globs vss-extension.json --token <your-personal-access-token>
```

> **Note:** You need a Personal Access Token with "Marketplace (publish)" scope from your Azure DevOps organization.

---

## 5. Install the Extension in Your Organization

1. Go to your Azure DevOps organization
2. Navigate to "Organization Settings" > "Extensions"
3. Click "Browse marketplace"
4. Search for "Sec1 Security" or install from the [uploaded extension](#4-publish-to-azure-devops-marketplace)
5. Click "Get it free" and install to your organization

---

## 6. Configure Service Connection

Before using the extension, set up a Generic Service Connection:

1. Go to "Project Settings" > "Service connections"
2. Click "New service connection" > "Generic" > "Next"
3. Configure:
   - **Server URL**: `https://api.sec1.io` (default)
   - **Username**: (optional - leave blank)
   - **Password/Token Key**: Your Sec1 API key from [Scopy](https://unified.sec1.io/)
   - **Service connection name**: `Sec1SecurityServiceConnection`
4. Save the connection

---

## 7. Test the Extension in a Pipeline

### Classic Pipeline
1. Edit your build pipeline
2. Add a new task and search for "Sec1 Security"
3. Configure the task:
   - Select your service connection
   - Enable SCA and/or SAST scans
   - Set vulnerability thresholds (optional)

### YAML Pipeline
Add the following to your `azure-pipelines.yml`:

```yaml
- task: Sec1Security@0
  inputs:
    serviceConnection: 'Sec1SecurityServiceConnection'
    enableSCA: true
    enableSAST: true
    thresholdCheck: true
    critical: '2'
    high: '5'
    medium: '10'
    low: '20'
```

---

## 8. Extension Configuration Reference

Based on [task.json](buildandreleasetask/task.json), the extension supports these inputs:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `serviceConnection` | connectedService:Generic | Yes | Sec1 API Key service connection |
| `enableSCA` | boolean | Yes | Enable Software Composition Analysis scan |
| `enableSAST` | boolean | Yes | Enable Static Application Security Testing scan |
| `packagePath` | filePath | No | Location of package file (pom.xml, package.json) |
| `thresholdCheck` | boolean | No | Enable vulnerability threshold checking |
| `critical` | string | No | Critical vulnerability threshold |
| `high` | string | No | High vulnerability threshold |
| `medium` | string | No | Medium vulnerability threshold |
| `low` | string | No | Low vulnerability threshold |

---

## 9. Troubleshooting

### Extension Not Found
- Ensure the extension is properly published and installed in your organization
- Check that the task ID `782b470c-fa25-41fd-b857-8e2f8dc60e88` matches the one in [task.json](buildandreleasetask/task.json)

### API Key Issues
- Verify your Sec1 API key is valid at [Scopy](https://unified.sec1.io/)
- Ensure the service connection is properly configured with the API key

### Build Failures
- Check pipeline logs for detailed error messages
- Verify that your repository contains supported package files (pom.xml for Maven, package.json for Node.js)
- Review the scan results in the provided report URL

### Package File Detection
The extension automatically detects package files in this order:
1. User-specified path via `packagePath` input
2. `pom.xml` in repository root
3. `package.json` in repository root

---

## 10. Version Management

To update the extension version:

1. Update version in [vss-extension.json](vss-extension.json) (currently `1.2.1`)
2. Update version in [buildandreleasetask/task.json](buildandreleasetask/task.json)
3. Rebuild and republish the extension

---

## References

- [Azure DevOps Extension Documentation](https://learn.microsoft.com/en-us/azure/devops/extend/)
- [tfx-cli Usage](https://learn.microsoft.com/en-us/azure/devops/extend/publish/command-line)
- [Extension Manifest Reference](https://learn.microsoft.com/en-us/azure/devops/extend/develop/manifest)
- [Sec1 Security Documentation](README.md)

---
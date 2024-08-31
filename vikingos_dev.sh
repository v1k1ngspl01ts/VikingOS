#!/bin/bash


# Create the directory for VS Code extensions
cd /opt/vikingos/coding
mkdir -p code_extensions
cd code_extensions

# VSCode Extensions for Cloud DevOps, Java, JavaScript, Databases, PowerShell, Atlassian Products, and C/C++

EXTENSIONS=(
    "github.vscode-pull-request-github"
    "gitlab.gitlab-workflow"
    "ms-python.python"
    "ms-python.vscode-pylance"
    "ms-azuretools.vscode-docker"
    "ms-kubernetes-tools.vscode-kubernetes-tools"
    "hashicorp.terraform"
    "redhat.vscode-yaml"
    "redhat.ansible"
    "ms-azuretools.vscode-bicep"
    "ms-vscode.vscode-node-azure-pack"
    "ms-vscode-remote.remote-ssh"
    "ms-vscode-remote.remote-containers"
    "ms-azure-devops.azure-pipelines"
    "humao.rest-client"
    "eamodio.gitlens"
    "esbenp.prettier-vscode"
    "yzhang.markdown-all-in-one"
    "mtxr.sqltools"
    "mtxr.sqltools-driver-mysql"
    "mtxr.sqltools-driver-pg"
    "mongodb.mongodb-vscode"
    "vscjava.vscode-java-pack"
    "shengchen.vscode-checkstyle"
    "sonarsource.sonarlint-vscode"
    "dbaeumer.vscode-eslint"
    "xabikos.javascriptsnippets"
    "christian-kohler.path-intellisense"
    "christian-kohler.npm-intellisense"
    "rbbit.typescript-hero"
    "ms-vscode.powershell"
    "atlassian.atlascode"
    "ms-vscode.cpptools"
    "ms-vscode.cpptools-extension-pack"
    "Oracle.oracle-java"
    "vscodevim.vim"
)

for extension in "${EXTENSIONS[@]}"; do
    code --install-extension "$extension" --no-sandbox
done

# Install Jira CLI tools
echo "Installing Jira CLI tools..."
npm install -g jira-cli

# Install Confluence CLI tools
echo "Installing Confluence CLI tools..."
npm install -g confluence-cli

# Install Bitbucket CLI tools
echo "Installing Bitbucket CLI tools..."
npm install -g bitbucket-cli

echo "Installing AWS SDK npm"
npm install -g aws-sdk


echo "Atlassian CLI tools installation complete."
echo "Development environment setup complete."



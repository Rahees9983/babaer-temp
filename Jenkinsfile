pipeline {
    agent any

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
    }

    tools {
        terraform 'terraform'  // Uses Terraform tool configured in Jenkins
    }

    environment {
        TF_IN_AUTOMATION = 'true'
        TF_INPUT = 'false'
    }

    parameters {
        choice(
            name: 'ACTION',
            choices: ['plan', 'apply', 'destroy'],
            description: 'Terraform action to perform'
        )
        choice(
            name: 'ENVIRONMENT',
            choices: ['dev', 'staging', 'prod'],
            description: 'Target environment'
        )
        booleanParam(
            name: 'AUTO_APPROVE',
            defaultValue: false,
            description: 'Auto approve terraform apply/destroy (use with caution!)'
        )
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'ls -la'
            }
        }

        stage('Terraform Version') {
            steps {
                sh 'terraform --version'
            }
        }

        stage('Terraform Init') {
            steps {
                dir('terraform') {
                    sh """
                        terraform init \
                            -backend-config="environments/${params.ENVIRONMENT}/backend.tfvars" \
                            -reconfigure
                    """
                }
            }
        }

        stage('Terraform Validate') {
            steps {
                dir('terraform') {
                    sh 'terraform validate'
                }
            }
        }

        stage('Terraform Format Check') {
            steps {
                dir('terraform') {
                    sh 'terraform fmt -check -recursive || true'
                }
            }
        }

        stage('Terraform Plan') {
            steps {
                dir('terraform') {
                    sh """
                        terraform plan \
                            -var-file="environments/${params.ENVIRONMENT}/terraform.tfvars" \
                            -out=tfplan
                    """
                }
            }
        }

        stage('Terraform Apply') {
            when {
                expression { params.ACTION == 'apply' }
            }
            steps {
                script {
                    if (params.AUTO_APPROVE) {
                        dir('terraform') {
                            sh 'terraform apply -auto-approve tfplan'
                        }
                    } else {
                        input message: 'Do you want to apply this plan?', ok: 'Apply'
                        dir('terraform') {
                            sh 'terraform apply -auto-approve tfplan'
                        }
                    }
                }
            }
        }

        stage('Terraform Destroy') {
            when {
                expression { params.ACTION == 'destroy' }
            }
            steps {
                script {
                    if (params.AUTO_APPROVE) {
                        dir('terraform') {
                            sh """
                                terraform destroy \
                                    -var-file="environments/${params.ENVIRONMENT}/terraform.tfvars" \
                                    -auto-approve
                            """
                        }
                    } else {
                        input message: 'Are you sure you want to DESTROY resources?', ok: 'Destroy'
                        dir('terraform') {
                            sh """
                                terraform destroy \
                                    -var-file="environments/${params.ENVIRONMENT}/terraform.tfvars" \
                                    -auto-approve
                            """
                        }
                    }
                }
            }
        }

        stage('Show Outputs') {
            when {
                expression { params.ACTION == 'apply' }
            }
            steps {
                dir('terraform') {
                    sh 'terraform output -json || true'
                }
            }
        }
    }

    post {
        success {
            echo "Pipeline completed successfully!"
            dir('terraform') {
                archiveArtifacts artifacts: 'deployment-*.txt', allowEmptyArchive: true
                archiveArtifacts artifacts: '*.tfstate', allowEmptyArchive: true
            }
        }
        failure {
            echo "Pipeline failed!"
            cleanWs()
        }
    }
}

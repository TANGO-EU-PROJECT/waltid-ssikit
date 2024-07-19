pipeline {
    agent {
        node {
            label 'Agent01'
        }
    }
    tools {
          jdk 'jdk17.0'
    }
    environment {
      APP_NAME = "ssikit"
      DOCKER_IMAGE = 'server'
      ARTIFACTORY_SERVER = "harbor.tango.rid-intrasoft.eu"
      ARTIFACTORY_DOCKER_REGISTRY = "harbor.tango.rid-intrasoft.eu/ssikit-waltid/"
      BRANCH_NAME = "main"
      DOCKER_IMAGE_TAG = "$APP_NAME:R${env.BUILD_ID}"
	TAG = 'v1.0'    
	KUBERNETES_NAMESPACE = 'ips-testing1'
	HARBOR_SECRET = 'harborsecret'
	CHART_NAME = 'ssikit'    
	CHART_PATH = 'Chart.yaml'
	RELEASE_NAME = 'ssikit'
    }

    stages {
      stage('Compile') {
          steps {
            dir('app') {
		    sh 'echo "JAVA_HOME=$JAVA_HOME"'
		    sh './ssikit.sh build-st'
                }
            }
        }
    


        stage('Build image') { // build and tag docker image
            steps {
                dir('app') {
                        echo 'Starting to build docker image'
                        script {
                            def dockerImage = docker.build(ARTIFACTORY_DOCKER_REGISTRY + DOCKER_IMAGE_TAG) 
                        }
                    }
                }
        }

	    stage("Push_Image"){
            steps {
                withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'harbor-jenkins-creds', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]){
                    echo "***** Push Docker Image *****"
                    sh 'docker login ${ARTIFACTORY_SERVER} -u ${USERNAME} -p ${PASSWORD}'
                    sh 'docker image push ${ARTIFACTORY_DOCKER_REGISTRY}${DOCKER_IMAGE_TAG}'
		    sh 'docker tag ${ARTIFACTORY_DOCKER_REGISTRY}${DOCKER_IMAGE_TAG} ${ARTIFACTORY_DOCKER_REGISTRY}${APP_NAME}:v1.0'
		    sh 'docker image push ${ARTIFACTORY_DOCKER_REGISTRY}${APP_NAME}:v1.0'
                }
            }
        }

      stage('Docker Remove Image locally') {
        steps {
                sh 'docker rmi "$ARTIFACTORY_DOCKER_REGISTRY$DOCKER_IMAGE_TAG"'
		sh 'docker rmi "$ARTIFACTORY_DOCKER_REGISTRY$APP_NAME:v1.0"'
            }
        }
    
      
      stage("Deployment"){
       	    steps {
               withKubeConfig([credentialsId: 'K8s-config-file' , serverUrl: 'https://kubernetes.tango.rid-intrasoft.eu:6443', namespace:'ips-testing1']) {
                 sh 'kubectl apply -f deployment.yaml'
		 sh 'kubectl apply -f service.yaml'
                 sh 'kubectl get pods -n ${KUBERNETES_NAMESPACE}'
               }
 
            }
      }
    }

}

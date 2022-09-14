pipeline { 
    agent any

    environment { 
        TEST="ENV vars go here"
        TOOLNAME="HavocFramework"
    }

    stages{
        stage('Cleanup'){
            steps{
                deleteDir()
                dir("${TOOLNAME}"){
                      deleteDir()
                }
            }
        }

        stage('Add-Havoc'){
                steps{
                        sh "pwd && ls"
                        sh "cp -R /Build/* ${WORKSPACE}/"
                }
        }
        
        stage('Build'){
                steps{
                        sh "pwd && ls"
                        sh "cd /Build/Build/ && make"
                }
        }
        
        stage('Sanity-Check'){
                steps{
                        sh 'ls /Build/Build/bin/'
                }
        }

    }
}

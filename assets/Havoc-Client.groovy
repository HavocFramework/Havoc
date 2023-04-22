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

//Local
//        stage('Add-Havoc'){
//                steps{
//                        sh "pwd && ls"
//                        sh "cp -R /Build/* ${WORKSPACE}/"
//                }
//        }

//Remote
      stage('Git Havoc'){
              steps{
                        sh 'git clone --single-branch --branch main https://github.com/HavocFramework/Havoc.git'
                }
        }

        stage('Build-1-make clean'){
                steps{
                        sh "cd ./Havoc/Client/ && make clean"
                }
        }

        stage('Build-2-make build dir'){
                steps{
                        sh "mkdir cd ./Havoc/Client/Build && cd ./Havoc/Client/Build && cmake .."
                }
        }
        stage('Build-3-make Build'){
                steps{
                        sh "cd ./Havoc/Client/ && cmake --build Build"
                }
        }

        stage('Sanity-Check'){
                steps{
                        sh 'file ./Havoc/Client/Havoc'
                }
        }

    }
}


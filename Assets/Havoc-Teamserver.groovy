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
//                      sh "pwd && ls"
//                      sh "cp -R /Build/* ${WORKSPACE}/"
//                }
//        }

//Remote
        stage('Git Havoc'){
                steps{
                        sh 'git clone --single-branch --branch main https://github.com/HavocFramework/Havoc.git'
                }
        }

        stage('Build'){
                steps{
                        sh "pwd && ls"
                        sh "cd ./Havoc/Teamserver/ && make"
                }
        }

        stage('Sanity-Check'){
                steps{
                        sh 'file ./Havoc/Teamserver/teamserver'
                }
        }

    }
}

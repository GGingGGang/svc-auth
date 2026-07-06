@Library('shared') _

pipeline {
  agent {
    kubernetes {
      label 'kaniko'
      defaultContainer 'kaniko'
    }
  }

  environment {
    SVC   = 'auth'
    IMAGE = "ghcr.io/${env.GH_ORG.toLowerCase()}/svc-${SVC}"
    TAG   = "${env.GIT_COMMIT}"
  }

  options {
    timestamps()
    disableConcurrentBuilds()
  }

  stages {
    stage('Build & Push') {
      steps {
        kanikoBuild(
          image: env.IMAGE,
          context: "dir://${env.WORKSPACE}",
          tags: [env.TAG, 'latest'],
          buildArgs: [GIT_SHA: env.GIT_COMMIT]
        )
      }
    }

    stage('Bump') {
      steps {
        deployBump(service: env.SVC, image: env.IMAGE, tag: env.TAG)
      }
    }
  }
}

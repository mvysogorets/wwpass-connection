rootProject.name = "WWPassConnection"

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"  // Provides automatic JDK downloading at build
    id("com.autonomousapps.build-health") version "3.0.1"  // Provides advice for managing dependencies and other applied plugins
    id("com.gradle.develocity") version "4.1.1"  // Publishes build scan to https://scans.gradle.com
    id("com.vanniktech.maven.publish") apply false version "0.34.0"  // Provides publishing to Maven Central
}

buildscript {
    configurations.getByName("classpath") {
        resolutionStrategy {  // Workaround for `org.owasp.dependencycheck`: https://github.com/dependency-check/DependencyCheck/issues/7405
            force("org.apache.commons:commons-compress:1.28.0")
        }
    }
}

@Suppress("UnstableApiUsage")
dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        google()
        mavenCentral()
    }
}

develocity {  // `com.gradle.develocity` plugin
    buildScan {
        // Allows connecting to https://scans.gradle.com without asking to agree to the terms of service each time
        termsOfUseUrl = "https://gradle.com/help/legal-terms-of-use"
        termsOfUseAgree = "yes"

        publishing.onlyIf {  // Publish only when building in CI
            System.getenv("CI_JOB_STAGE")?.lowercase() == "build"
        }
    }
}

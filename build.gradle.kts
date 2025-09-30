base.archivesName = rootProject.name

version = "1.5.1"

plugins {
    id("java-library")
    id("com.vanniktech.maven.publish")
    id("com.android.lint") version "8.13.0"  // Provides linting for .kts files
    id("org.owasp.dependencycheck") version "12.1.3"  // Checks dependencies for vulnerabilities
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)  // 17 is the last Java LTS version able to generate Java 1.8 bytecode
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.withType<JavaCompile> {
    options.isDeprecation = true
    options.compilerArgs.add("-Xlint:all")
    options.compilerArgs.add("-Werror")
}

tasks.jar {
    destinationDirectory = file("dist")
}

sourceSets {
    main {
        java {
            srcDir("src")
            include("com/wwpass/WWPassConnection.java")
        }
    }
}

dependencies {
    implementation("com.googlecode.json-simple:json-simple:1.1.1") {
        exclude("junit", "junit")  // Old vulnerable v4.10 is used and is not needed
    }
    implementation("commons-codec:commons-codec:1.19.0")
    implementation("jakarta.servlet:jakarta.servlet-api:6.1.0")
    lintChecks("androidx.lint:lint-gradle:1.0.0-alpha05")
}

dependencyCheck {  // Plugin: org.owasp.dependencycheck
    format = "ALL"
    outputDirectory = "$rootDir/build/reports/dependency-check"
    failOnError = true

    nvd {
        // Obtained from https://nvd.nist.gov/developers/request-an-api-key
        // Stored at https://gitlab.wwpass.net/admin/application_settings/ci_cd#js-ci-cd-variables
        apiKey = System.getenv("NVD_API_KEY")
    }
}

mavenPublishing {  // Credentials are stored at https://gitlab.wwpass.net/admin/application_settings/ci_cd#js-ci-cd-variables
    publishToMavenCentral()  // Add `automaticRelease = true` to push deployment to Maven Central right away
    signAllPublications()

    coordinates("com.wwpass", "wwpass-connection", version as String?)

    pom {
        name = "wwpass-connection"
        description = "WWPass Service Provider Java SDK."
        inceptionYear.set("2014")
        url = "https://github.com/wwpass/wwpass-connection"

        licenses {
            license {
                name = "The Apache License, Version 2.0"
                url = "http://www.apache.org/licenses/LICENSE-2.0.txt"
                distribution = "http://www.apache.org/licenses/LICENSE-2.0.txt"
            }
        }

        developers {
            developer {
                id = "wwpass"
                name = "WWPass Corporation"
                url = "https://github.com/wwpass"
            }
        }

        scm {
            url = "https://github.com/wwpass/wwpass-connection"
            connection = "scm:git:git://github.com/wwpass/wwpass-connection.git"
            developerConnection = "scm:git:ssh://git@github.com/wwpass/wwpass-connection.git"
        }
    }
}

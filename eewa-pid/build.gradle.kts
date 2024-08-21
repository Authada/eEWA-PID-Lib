/*
 * Copyright (c) 2024 AUTHADA GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.gradle.api.JavaVersion
import org.jetbrains.kotlin.gradle.plugin.KotlinAndroidPluginWrapper

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    id("maven-publish")
}

android {
    namespace = "de.authada.eewa.pid.lib"
    group = "de.authada.eewa"
    compileSdk = 33

    defaultConfig {
        minSdk = 28
        targetSdk = 33

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.toVersion(libs.versions.java.get())
        targetCompatibility = JavaVersion.toVersion(libs.versions.java.get())
    }

    kotlinOptions {
        jvmTarget = libs.versions.java.get()
    }

    apply<KotlinAndroidPluginWrapper>()
    sourceSets {
        getByName("main") {
            java.srcDir("src/main/kotlin")
        }
        getByName("test") {
            java.srcDir("src/test/kotlin")
        }
    }
}

dependencies {
    implementation(libs.bcprov)
    implementation(libs.gson)
}

project.afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("maven") {
                project.afterEvaluate {
                    groupId = "de.authada.eewa"
                    artifactId = "eewa-pid-lib"
                    version = "1.0"
                    pom {
                        licenses {
                            license {
                                name = "AUTHADA GmbH License"
                                url = "https://www.authada.de"
                                distribution = "repo"
                            }
                        }
                    }
                    from(components.findByName("release"))
                }
            }
        }
    }
}
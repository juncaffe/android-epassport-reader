plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.maven.publish)
}

group = "io.github.juncaffe"
version = rootProject.extra["epassport_version"] as String

android {
    namespace = "com.juncaffe.epassport"
    compileSdk = libs.versions.compile.sdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.min.sdk.get().toInt()

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    publishing {
        singleVariant("release") {
            withSourcesJar()
//            withJavadocJar()
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "io.github.juncaffe"
                artifactId = "epassport-reader"
                version = rootProject.extra["epassport_version"] as String

                pom {
                    name.set("Android ePassport Reader")
                    description.set("JMRTD-Lite based ePassport reader for Android")
                    url.set("https://github.com/juncaffe/android-epassport-reader")
                    licenses {
                        license {
                            name.set("LGPL-2.1")
                            url.set("https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html")
                        }
                    }
                    developers {
                        developer {
                            id.set("juncaffe")
                            name.set("JunCaffe")
                            url.set("https://github.com/juncaffe")
                        }
                    }
                }
            }
        }
        repositories {
            maven {
                name = "GitHubPackages"
                url = uri("https://maven.pkg.github.com/juncaffe/android-epassport-reader")
                credentials {
                    username = System.getenv("GITHUB_ACTOR")
                    password = System.getenv("GITHUB_TOKEN")
                }
            }
        }
    }
}

tasks.register<Copy>("copyAarToApp") {
    dependsOn("assembleRelease")
    from(layout.buildDirectory.dir("outputs/aar"))
    into(rootProject.file("app/libs"))
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
//    api(project(":jmrtdlite"))
    api(fileTree("libs") { include("*.jar") })
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

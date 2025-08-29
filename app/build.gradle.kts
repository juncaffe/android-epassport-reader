import org.gradle.kotlin.dsl.implementation
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
}

android {
    namespace = "com.juncaffe.jmrtd_android"
    compileSdk = libs.versions.compile.sdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.min.sdk.get().toInt()
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // @Module 클래스를 검사 disable(임시)
        javaCompileOptions {
            annotationProcessorOptions {
                arguments["dagger.hilt.disableModulesHaveInstallInCheck"] = "true"
            }
        }
    }
    hilt {
        enableAggregatingTask = false
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
    buildFeatures {
        compose = true
    }

    packaging {
        resources {
            excludes += setOf(
                "META-INF/versions/**",
                "META-INF/DEPENDENCIES",
                "META-INF/LICENSE*",
                "META-INF/NOTICE*"
            )
        }
    }
}

kotlin {
    jvmToolchain(17)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

//tasks.register<Copy>("copyMrtdJarToLibs") {
//    dependsOn(":mrtd:exportJar")
//    val jarOutput = layout.buildDirectory.dir("mrtd/build/outputs/jar")
//    from("$jarOutput/mrtd*.jar")
//    into(layout.buildDirectory.dir("app/libs"))
//}

//tasks.named("preBuild") {
//    dependsOn(":jmrtdlite:copyJarToEpassport")
//}

dependencies {
//    implementation(project(":ePassport"))
    implementation("com.github.juncaffe:android-epassport-reader:v0.0.10")
    implementation(libs.bundles.androidx)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.bundles.compose)

    implementation(libs.bundles.jmrtd)
    implementation(libs.hilt.navigation.compose)
    implementation(libs.dagger.hilt)
    ksp(libs.dagger.compiler)

    testImplementation(libs.junit)
    androidTestImplementation(libs.bundles.test)
    androidTestImplementation(libs.bundles.test)
    debugImplementation(libs.bundles.ui.debug)
}
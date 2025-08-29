plugins {
    id("java-library")
    alias(libs.plugins.jetbrains.kotlin.jvm)
}
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

tasks.register<Jar>("exportJar") {
    from(sourceSets.main.get().output)
    archiveBaseName.set("jmrtd-lite")
    archiveVersion.set("0.1")
    destinationDirectory.set(layout.buildDirectory.dir("outputs/jar"))
}
tasks.register<Copy>("copyJarToEpassport") {
    dependsOn("exportJar")
    from(layout.buildDirectory.dir("outputs/jar"))
    into(rootProject.file("epassport/libs"))
}

dependencies {
    implementation(libs.bundles.jmrtd)
    testImplementation(libs.junit)
}
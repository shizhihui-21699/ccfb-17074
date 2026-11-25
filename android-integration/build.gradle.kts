plugins {
    kotlin("jvm")
}

dependencies {
    api(project(":secure-core"))
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.1.20")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.11.4")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.11.4")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.4")
}

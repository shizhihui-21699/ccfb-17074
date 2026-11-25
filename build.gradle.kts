// 全项目离线可复现构建：版本全部锁定为本机 Gradle 缓存中已存在的构件。
plugins {
    kotlin("jvm") version "2.1.20" apply false
}

allprojects {
    repositories {
        mavenCentral()
        google()
    }
}

subprojects {
    plugins.withId("org.jetbrains.kotlin.jvm") {
        extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension> {
            compilerOptions {
                jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
            }
        }
    }
    tasks.withType<JavaCompile>().configureEach {
        sourceCompatibility = "17"
        targetCompatibility = "17"
    }
    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
    }
}

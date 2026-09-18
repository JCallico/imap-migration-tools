import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.Properties

val localProperties = Properties().apply {
    val propertiesFile = rootProject.file("local.properties")
    if (propertiesFile.isFile) propertiesFile.inputStream().use(::load)
}

fun localProperty(name: String): String = localProperties.getProperty(name, "").trim()

fun buildConfigString(value: String): String = "\"${value.replace("\\", "\\\\").replace("\"", "\\\"")}\""

val microsoftClientId = localProperty("oauth.microsoft.clientId")
val microsoftRedirectUri = localProperty("oauth.microsoft.redirectUri")
val microsoftSignatureHash = localProperty("oauth.microsoft.signatureHash")

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.chaquo.python")
}

android {
    namespace = "com.callicode.imaptools"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.callicode.imaptools"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0-alpha01"

        buildConfigField("String", "MICROSOFT_CLIENT_ID", buildConfigString(microsoftClientId))
        buildConfigField("String", "MICROSOFT_REDIRECT_URI", buildConfigString(microsoftRedirectUri))
        manifestPlaceholders["msalSignatureHash"] = microsoftSignatureHash

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables.useSupportLibrary = true
        ndk.abiFilters += listOf("arm64-v8a", "x86_64")
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging.resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

chaquopy {
    defaultConfig {
        version = "3.13"
        pyc {
            src = true
        }
    }
    sourceSets {
        getByName("main") {
            srcDir("../../src")
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.12.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.activity:activity-compose:1.11.0")
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.4")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.9.4")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.9.4")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("com.google.android.gms:play-services-auth:21.5.1")
    implementation("com.microsoft.identity.client:msal:8.4.1")
    debugImplementation("androidx.compose.ui:ui-tooling")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:rules:1.6.1")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

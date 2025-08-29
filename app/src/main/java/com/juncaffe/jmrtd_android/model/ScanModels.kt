package com.juncaffe.jmrtd_android.model

enum class ScanStatus { Idle, Authentication, Scanning, Done, Error }

data class ScanUiState(
    val status: ScanStatus = ScanStatus.Idle,
    val overallProgress: Int = 0,
    val stageProgress: LinkedHashMap<String, Int> = linkedMapOf(),
    val dg2ImageBytes: ByteArray? = null,
    val message: String? = null,
    val errorMessage: String? = null
)
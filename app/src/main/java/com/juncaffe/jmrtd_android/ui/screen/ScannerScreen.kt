package com.juncaffe.jmrtd_android.ui.screen

import android.graphics.BitmapFactory
import android.util.Log
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Image
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import com.juncaffe.jmrtd_android.model.ScanStatus
import com.juncaffe.jmrtd_android.model.ScanUiState
import com.juncaffe.jmrtd_android.presentation.EPassportViewModel
import com.juncaffe.jmrtd_android.presentation.PassportViewModel
import com.juncaffe.jmrtd_android.ui.component.PulsingPlaceholderBar
import com.juncaffe.jmrtd_android.ui.component.SmoothProgress
import com.juncaffe.jmrtd_android.ui.component.StageProgress

@Composable
fun ScannerScreen(
    navController: NavController,
    sharedViewModel: PassportViewModel,
    viewModel: EPassportViewModel = hiltViewModel(),
) {
    LaunchedEffect(Unit) {
        val bacKey = sharedViewModel.getBACKey()
        viewModel.setBacKey(bacKey)
    }

    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    val scroll = rememberScrollState()

    val imageBitmap = remember(uiState.dg2ImageBytes) {
        uiState.dg2ImageBytes?.let { bytes ->
            runCatching { BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.asImageBitmap() }.getOrNull()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.Start
    ) {
        Text(
            text = "여권 스캔",
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.Start)
                .padding(horizontal = 16.dp, vertical = 12.dp)
        )
        AnimatedContent(
            targetState = uiState.status,
            transitionSpec = {(fadeIn(animationSpec = tween(200)) togetherWith fadeOut(animationSpec = tween(200)))},
            label = "status-content"
        ) { status ->
            when(status) {
                ScanStatus.Idle -> IdleContent({ viewModel.onStart() })
                ScanStatus.Authentication -> AuthenticationContent(uiState)
                ScanStatus.Scanning -> ScanningContent(uiState)
                ScanStatus.Done -> DoneContent(imageBitmap)
                ScanStatus.Error -> ErrorContent(uiState.errorMessage?:"알 수 없는 오류", {
                    navController.navigate("secure_keypad") {
                        // 뒤로가기에서 제거
                        popUpTo("scanner") { inclusive = true }
                    }
                })
            }
        }
    }
}

@Composable
fun IdleContent(
    onStartScan: () -> Unit,
) {
    Column(Modifier
        .fillMaxSize()
        .padding(horizontal = 16.dp)) {
        Text("대기 중입니다. 스캔을 시작해주세요.")
        Spacer(Modifier.height(12.dp))
        Button(onClick = onStartScan) { Text("스캔 시작") }
    }
}


@Composable
fun AuthenticationContent(
    uiState: ScanUiState,
) {
    Column(Modifier
        .fillMaxSize()
        .padding(horizontal = 16.dp)) {
        Text("${uiState.message} 진행 중")
    }
}

@Composable
fun ScanningContent(
    uiState: ScanUiState,
) {
    Column(Modifier
        .fillMaxSize()
        .padding(horizontal = 16.dp)) {
        Text("전체 진행률: ${uiState.overallProgress}%")
        SmoothProgress(
            progress = uiState.overallProgress,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        if(uiState.stageProgress.isEmpty()) {
            Text("단계 준비 중...")
            PulsingPlaceholderBar()
        }else {
            uiState.stageProgress.forEach { (stage, progress) ->
                Text("$stage: $progress%")
                StageProgress(
                    progress = progress,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
            }
        }
    }
}

@Composable
fun DoneContent(
    imageBitmap: ImageBitmap?
) {
    Column(Modifier
        .fillMaxSize()
        .padding(horizontal = 16.dp)) {
        Text("스캔 완료", style = MaterialTheme.typography.titleMedium)
        LinearProgressIndicator(
            progress = { 1f },
            modifier = Modifier
                .fillMaxWidth()
                .height(8.dp)
        )
        Spacer(Modifier.height(8.dp))
        Text("DG2 이미지")
        AnimatedVisibility(
            visible = imageBitmap != null,
            enter = fadeIn(animationSpec = tween(250)),
            exit = fadeOut(animationSpec = tween(200)),
        ) {
            imageBitmap?.let {
                Image(
                    bitmap = it,
                    contentDescription = "Face",
                    modifier = Modifier
                        .fillMaxWidth()
                        .aspectRatio(3f / 4f)
                        .clip(RoundedCornerShape(12.dp))
                        .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(12.dp)),
                    contentScale = ContentScale.Crop
                )
            }?:run {
                Text("이미지를 표시할 수 없습니다.")
            }
        }
    }
}

@Composable
fun ErrorContent(
    error: String,
    onRetry: () -> Unit
) {
    Column(Modifier
        .fillMaxSize()
        .padding(horizontal = 16.dp)) {
        Text("오류가 발생했습니다.", color = MaterialTheme.colorScheme.error)
        Spacer(Modifier.height(4.dp))
        Text(error)
        Spacer(Modifier.height(12.dp))
        Button(onClick = onRetry) { Text("재시도") }
    }
}
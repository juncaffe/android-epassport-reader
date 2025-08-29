package com.juncaffe.jmrtd_android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.compose.rememberNavController
import com.juncaffe.jmrtd_android.data.NFCManager
import com.juncaffe.jmrtd_android.presentation.EPassportViewModel
import com.juncaffe.jmrtd_android.ui.screen.AppNavHost
import com.juncaffe.jmrtd_android.ui.screen.ScannerScreen
import com.juncaffe.jmrtd_android.ui.screen.SecureKeypadScreen
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayOutputStream
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    @Inject
    lateinit var nfcManager: NFCManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
//        enableEdgeToEdge()

        nfcManager.setCurrentActivity(this)
        setContent {
            val navController = rememberNavController()
            AppNavHost(navController)
        }
    }

    override fun onResume() {
        super.onResume()
        nfcManager.setCurrentActivity(this)
    }

    override fun onPause() {
        super.onPause()
    }

//    @Composable
//    fun ScreenHost(viewModel: EPassportViewModel = hiltViewModel()) {
//        val uiState by viewModel.uiState.collectAsStateWithLifecycle()
//        SecureKeypadScreen() { passportNo, birth, expire ->  }
////        ScannerScreen(
////            uiState = uiState,
////            onStartScan = {
////                viewModel.onStart()
////            }
////        )
//    }

    /**
     * ByteArrayOutputStream 사용한 메모리 0으로 덮어쓰기 (클리어)
     */
    fun ByteArrayOutputStream.clear(fillByte: Byte = 0) {
        // 메모리 덮어쓰기 (클리어)
        val bufferField = ByteArrayOutputStream::class.java.getDeclaredField("buf")
        bufferField.isAccessible = true
        val internalBuffer = bufferField.get(this) as ByteArray
        internalBuffer.fill(fillByte)
        this.reset()
    }

//    override fun onStart() {
//        super.onStart()
//        val nfcManager = applicationContext.getSystemService(NFC_SERVICE) as NfcManager
//        nfcManager.defaultAdapter.enableReaderMode(this, readerCallback, NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B, Bundle())
//    }
//
//    override fun onStop() {
//        super.onStop()
//        val nfcManager = applicationContext.getSystemService(NFC_SERVICE) as NfcManager
//        nfcManager.defaultAdapter.disableReaderMode(this)
//    }
}
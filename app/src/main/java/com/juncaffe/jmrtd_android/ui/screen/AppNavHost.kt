package com.juncaffe.jmrtd_android.ui.screen

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.navigation
import com.juncaffe.jmrtd_android.presentation.PassportViewModel

@Composable
fun AppNavHost(navController: NavHostController) {
    NavHost(
        navController = navController,
        startDestination = "scan"
    ) {
        navigation(route = "scan", startDestination = "secure_keypad") {
            composable("secure_keypad") { backStackEntry ->
                val parentEntry = remember(backStackEntry) {
                    navController.getBackStackEntry("scan")
                }
                val sharedViewModel: PassportViewModel = hiltViewModel(parentEntry)
                SecureKeypadScreen(navController, sharedViewModel)
            }
            composable("scanner") { backStackEntry ->
                val parentEntry = remember(backStackEntry) {
                    navController.getBackStackEntry("scan")
                }
                val sharedViewModel: PassportViewModel = hiltViewModel(parentEntry)
                ScannerScreen(navController, sharedViewModel = sharedViewModel)
            }
        }
    }
}
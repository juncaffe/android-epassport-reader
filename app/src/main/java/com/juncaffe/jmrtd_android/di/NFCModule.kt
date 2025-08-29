package com.juncaffe.jmrtd_android.di

import android.content.Context
import com.juncaffe.jmrtd_android.data.NFCManager
import com.juncaffe.jmrtd_android.data.NFCRepository
import com.juncaffe.jmrtd_android.data.NFCRepositoryImpl
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton


@Module
@InstallIn(SingletonComponent::class)
object NFCModule {

    @Provides
    @Singleton
    fun provideNFCManager(@ApplicationContext context: Context): NFCManager {
        return NFCManager(context)
    }

    @Provides
    @Singleton
    fun provideNFCRepository(nfcManager: NFCManager): NFCRepository {
        return NFCRepositoryImpl(nfcManager)
    }
}
package com.juncaffe.epassport.api

import com.juncaffe.epassport.model.State
import com.juncaffe.epassport.mrtd.PassportService

interface EPassportCallback {
    fun onState(state: State) {}
    fun onProgress(fid: PassportService.EF, currentReadSize: Int, dgAccumulatedReadSize: Int, dgSize: Int, totalDgSize: Int) {}
    fun onComplete() {}
    fun onError(t: Throwable) {}
}
package com.juncaffe.epassport.model

import com.juncaffe.epassport.mrtd.PassportService

sealed class State() {
    object CardAccess: State()
    object Sign: State()
    object ChipAuthentication: State()
    object PassiveAuthentication: State()
    data class Reading(val fid: PassportService.EF): State()
}

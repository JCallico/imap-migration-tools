package com.callicode.imaptools.operation

import com.callicode.imaptools.model.OperationState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

object OperationBus {
    private val mutableState = MutableStateFlow(OperationState())
    val state = mutableState.asStateFlow()

    fun update(transform: (OperationState) -> OperationState) {
        mutableState.value = transform(mutableState.value)
    }
}

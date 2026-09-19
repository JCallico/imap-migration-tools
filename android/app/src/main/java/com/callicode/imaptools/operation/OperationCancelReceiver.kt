package com.callicode.imaptools.operation

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class OperationCancelReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        OperationDispatcher.cancel(context)
    }
}

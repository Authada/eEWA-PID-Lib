/*
 * Copyright (c) 2024 AUTHADA GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.authada.eewa.secure_element

import android.app.Activity
import android.se.omapi.Channel
import android.se.omapi.Reader
import android.se.omapi.SEService
import android.se.omapi.Session
import android.util.Log
import java.io.IOException

class SecureElementWrapper(private val secureElementCallback: SecureElementCallback) {
    private var service: SEService? = null
    private var eSE: Reader? = null
    private var ch: Channel? = null
    private var session: Session? = null
    private val tag = "SecureElementWrapper"

    private val fidesmoAppletAid = byteArrayOf(
        0xA0.toByte(), 0x00.toByte(), 0x00.toByte(),
        0x06.toByte(), 0x17.toByte(), 0x00.toByte(),
        0x1D.toByte(), 0x65.toByte(), 0x16.toByte(),
        0xBC.toByte(), 0x01.toByte()
    )

    fun init(activity: Activity) {
        try {
            service = SEService(activity, SynchronousExecutor(), mListener)
        } catch (e: Exception) {
            Log.e(tag, "SEService Exception: " + e.message)
        }
    }

    private val mListener = SEService.OnConnectedListener {
        val readers = service?.readers

        readers?.let {
            Log.d(tag, "reader da")
            eSE = readers.firstOrNull { reader ->
                reader.name.startsWith(ESE_TAG) || reader.name.startsWith(SIM_TAG)
            }
        }

        eSE?.let {
            Log.d(tag, "eSE da")

            it.openChannel()
        } ?: secureElementCallback.onConnectionCouldntBeEstablished("Kein Secure Element")
    }

    private fun Reader.openChannel() {
        try {
            session = openSession()
            ch = session!!.openLogicalChannel(fidesmoAppletAid)

            ch?.let { channel ->
                Log.d(tag, "Session open")
                channel.selectResponse?.let { it1 ->
                    val responseString = it1.toHexString()
                    Log.d(tag, responseString)
                    if (responseString.startsWith("90")) {
                        secureElementCallback.onConnected()
                    } else {
                        secureElementCallback.onConnectionCouldntBeEstablished("Channel wurde nicht aufgebaut")
                    }
                }
            } ?: secureElementCallback.onConnectionCouldntBeEstablished("Channel wurde nicht gefunden")
        } catch (e: SecurityException) {
            e.message?.let { it2 ->
                Log.d(tag, "Error")
                Log.d(tag, it2)
                secureElementCallback.onConnectionCouldntBeEstablished("TBASIC: $it2")
            }
        } catch(e: Exception) {
            Log.d(tag, "Error: ${e.message ?: "unknown error"}")
            secureElementCallback.onConnectionCouldntBeEstablished("Error: ${e.message ?: "unknown error"}")
        }
    }


    @Throws(SecureElementClosedException::class)
    fun transmit(command: ByteArray, name: String): String {
        val pureTransmitResponse = pureTransmit(command, name)
        return if (pureTransmitResponse.isEmpty())
            ""
        else
            pureTransmitResponse.toHexString()
    }


    @Throws(SecureElementClosedException::class)
    fun pureTransmit(command: ByteArray, name: String): ByteArray {
        Log.d(tag, name + " Request: " + command.toHexString())
        return runCatching {
            trySend(command, name)
        }.recover {
            if (
                it is SecureElementClosedException ||
                it is IOException ||
                it is IllegalStateException
            ) {
                eSE?.openChannel()
            }
            trySend(command, name)
        }.getOrThrow()
    }

    private fun trySend(command: ByteArray, name: String): ByteArray {
        ch?.let {
            if (it.isOpen) {
                val response = it.transmit(command)
                Log.d(tag, name + " Response: ${response.toHexString()}")
                return response

            } else {
                throw SecureElementClosedException()
            }
        } ?: throw SecureElementClosedException()
    }

    fun closeChannel() {
        eSE?.closeSessions()
    }

    fun freeResources() {
        eSE?.closeSessions()
    }

    companion object {
        private const val ESE_TAG: String = "eSE"
        private const val SIM_TAG: String = "SIM"
    }
}
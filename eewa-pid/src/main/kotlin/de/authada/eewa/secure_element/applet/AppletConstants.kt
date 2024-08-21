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

package de.authada.eewa.secure_element.applet

object AppletConstants {
    const val cla = 0x84.toByte()
    const val claChained = 0x94.toByte()
    const val insVerifyPin = 0x20.toByte()
    const val insDeleteTransients = 0x35.toByte()
    const val insPopAndAttestation = 0x39.toByte()
    const val insCreatePersonalData = 0x42.toByte()
    const val insCreatePid = 0x43.toByte()
    const val insGetAuthenticationPK = 0x45.toByte()
    const val insGetDevicePK = 0x46.toByte()
    const val insSetPin = 0x51.toByte()
    const val insCleanUp = 0x71.toByte()
    const val insCreateSignatureWithDeviceKey = 0x72.toByte()
    const val insCreateHasPin = 0x73.toByte()
    const val insGetPersonalData = 0x44.toByte()

    const val p1 = 0x00.toByte()
    const val p2 = 0x00.toByte()

    const val maximumLe = 0x00.toByte()
    const val dataExtendedSizeMin = 256

    //status words
    const val SW_WALLET_BLOCKED: String = "63C0"
    const val SW_PIN_ONE_TRY_LEFT: String = "63C1"
    const val SW_PIN_TWO_TRIES_LEFT: String = "63C2"
    const val SW_NO_DATA_STORED: String = "6320"
    const val SW_SUCCESS: String = "9000"
}
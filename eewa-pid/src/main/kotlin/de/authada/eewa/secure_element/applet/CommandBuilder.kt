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

import android.util.Log
import de.authada.eewa.secure_element.Util.concat
import de.authada.eewa.secure_element.applet.AppletConstants.dataExtendedSizeMin
import de.authada.eewa.secure_element.applet.AppletConstants.maximumLe
import de.authada.eewa.secure_element.decodeHex

class CommandBuilder {
    fun createVerifyPin(pin: IntArray): ByteArray = byteArrayOf(
        AppletConstants.cla,
        AppletConstants.insVerifyPin,
        AppletConstants.p1,
        AppletConstants.p2,
        pin.size.toByte(),
        pin[0].toByte(),
        pin[1].toByte(),
        pin[2].toByte(),
        pin[3].toByte(),
        pin[4].toByte(),
        pin[5].toByte()
    )

    fun createObjectDeletion(): ByteArray = byteArrayOf(
        AppletConstants.cla,
        AppletConstants.insDeleteTransients,
        AppletConstants.p1,
        AppletConstants.p2
    )

    fun createHasPin(): ByteArray = byteArrayOf(
        AppletConstants.cla,
        AppletConstants.insCreateHasPin,
        AppletConstants.p1,
        AppletConstants.p2
    )


    private fun elLengthCommandBuilder(lengthOfData: ByteArray): ByteArray =
        when (lengthOfData.size) {
            1 -> concat(byteArrayOf(0x00.toByte(), 0x00.toByte()), lengthOfData)
            2 -> concat(byteArrayOf(0x00.toByte()), lengthOfData)
            3 -> lengthOfData
            else -> throw IllegalArgumentException("SIZE NOT Valid")
        }

    private fun elLengthExpectedBuilder(lengthOfData: ByteArray): ByteArray =
        when (lengthOfData.size) {
            1 -> concat(byteArrayOf(0x00.toByte()), lengthOfData)
            2 -> lengthOfData
            else -> throw IllegalArgumentException("SIZE NOT Valid")
        }

    private fun intToBytes(i: Int): ByteArray {
        var hexLength = Integer.toHexString(i)
        if (hexLength.length % 2 == 1) {
            hexLength = "0$hexLength"
        }
        Log.d("WALLETLOG", "HexLength: $hexLength")

        return hexLength.decodeHex()
    }


    fun createSetPinCommand(pin: IntArray): ByteArray = byteArrayOf(
        AppletConstants.cla,
        AppletConstants.insSetPin,
        AppletConstants.p1,
        AppletConstants.p2,
        pin.size.toByte(),
        pin[0].toByte(),
        pin[1].toByte(),
        pin[2].toByte(),
        pin[3].toByte(),
        pin[4].toByte(),
        pin[5].toByte()
    )

    fun createGetAuthenticationPK(): ByteArray = byteArrayOf(
        AppletConstants.cla,
        AppletConstants.insGetAuthenticationPK,
        AppletConstants.p1,
        AppletConstants.p2,
        0x00.toByte()
    )

    fun createGetDevicePK(): ByteArray = byteArrayOf(
        AppletConstants.cla,
        AppletConstants.insGetDevicePK,
        AppletConstants.p1,
        AppletConstants.p2,
        0x00.toByte()
    )

    fun createSignWithDevKey(nonce: ByteArray, splitted: Boolean = false): ByteArray {
        val begin = byteArrayOf(
            if (splitted) AppletConstants.claChained else AppletConstants.cla,
            AppletConstants.insCreateSignatureWithDeviceKey,
            AppletConstants.p1,
            AppletConstants.p2
        )

        val bytesLengthCommand = intToBytes(nonce.size)
        val extendedLengthData = nonce.isExtendedLengthData()

        return concat(
            begin,
            if (extendedLengthData) elLengthCommandBuilder(bytesLengthCommand) else bytesLengthCommand,
            nonce,
            if (extendedLengthData) elLengthExpectedBuilder(byteArrayOf(maximumLe)) else byteArrayOf(maximumLe)
        )
    }

    fun createPopAndAttestation(nonce: ByteArray): ByteArray {
        val begin = byteArrayOf(
            AppletConstants.cla,
            AppletConstants.insPopAndAttestation,
            AppletConstants.p1,
            AppletConstants.p2
        )
        val bytesLengthCommand = intToBytes(nonce.size)

        return concat(
            begin,
            bytesLengthCommand,
            nonce,
            byteArrayOf(maximumLe)
        )
    }

    fun createPersonalData(personalData: ByteArray): ByteArray {
        val begin = byteArrayOf(
            AppletConstants.cla,
            AppletConstants.insCreatePersonalData,
            AppletConstants.p1,
            AppletConstants.p2
        )

        val bytesLengthCommand = intToBytes(personalData.size)
        val extendedLengthData = personalData.isExtendedLengthData()

        return concat(
            begin,
            if (extendedLengthData) elLengthCommandBuilder(bytesLengthCommand) else bytesLengthCommand,
            personalData,
            if (extendedLengthData) elLengthExpectedBuilder(byteArrayOf(maximumLe)) else byteArrayOf(maximumLe)
        )
    }

    fun createCleanUp(): ByteArray {
        return byteArrayOf(
            AppletConstants.cla,
            AppletConstants.insCleanUp,
            AppletConstants.p1,
            AppletConstants.p2
        )
    }

    fun createPid(
        xByteArray: ByteArray,
        yByteArray: ByteArray,
        cr: ByteArray,
        iatByteArray: ByteArray,
        auditorByteArray: ByteArray,
        nonce: ByteArray,
        selector: ByteArray
    ): ByteArray {
        val foreignPublicKey = concat(
            byteArrayOf(0x04.toByte()), xByteArray, yByteArray
        )

        val foreignPublicKeyLength = intToBytes(foreignPublicKey.size)
        val crLength = intToBytes(cr.size)

        val body = concat(
            byteArrayOf(0x00),
            foreignPublicKeyLength,
            foreignPublicKey,
            byteArrayOf(0x00),
            crLength,
            cr,
            byteArrayOf(0x00),
            intToBytes(iatByteArray.size),
            iatByteArray,
            byteArrayOf(0x00),
            intToBytes(auditorByteArray.size),
            auditorByteArray,
            byteArrayOf(0x00),
            intToBytes(nonce.size),
            nonce,
            byteArrayOf(0x00),
            intToBytes(selector.size),
            selector
        )

        val (p1, data) = adjustP1AndDataForEL(body)

        val begin = byteArrayOf(
            AppletConstants.cla,
            AppletConstants.insCreatePid,
            p1,
            AppletConstants.p2
        )

        return concat(
            begin,
            elLengthCommandBuilder(intToBytes(data.size)),
            data,
            elLengthExpectedBuilder(byteArrayOf(maximumLe))
        )

    }
    fun getPersonalData(
        cr: ByteArray
    ): ByteArray {

        val body = concat(cr)
        val (p1, data) = adjustP1AndDataForEL(body)

        val begin = byteArrayOf(
            AppletConstants.cla,
            AppletConstants.insGetPersonalData,
            p1,
            AppletConstants.p2
        )

        return concat(
            begin,
            elLengthCommandBuilder(intToBytes(data.size)),
            data,
            elLengthExpectedBuilder(byteArrayOf(maximumLe))
        )
    }

    private fun adjustP1AndDataForEL(data: ByteArray): Pair<Byte, ByteArray> =
        if (data.size < dataExtendedSizeMin) {
            val missingLength = dataExtendedSizeMin - data.size
            val missingBytes = ByteArray(missingLength)
            missingBytes.fill(0x00)
            val oldSize = data.size.toByte()
            val adjustedData = concat(missingBytes, data)
            oldSize to adjustedData
        } else {
            AppletConstants.p1 to data
        }

    private fun ByteArray.isExtendedLengthData(): Boolean = this.size >= dataExtendedSizeMin
}
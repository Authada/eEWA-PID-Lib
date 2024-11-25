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

import de.authada.eewa.secure_element.Util.concat
import de.authada.eewa.secure_element.Util.intToBytes
import de.authada.eewa.secure_element.applet.AppletConstants.dataExtendedSizeMin
import de.authada.eewa.secure_element.applet.AppletConstants.keyidTag
import de.authada.eewa.secure_element.applet.AppletConstants.maximumLe
import de.authada.eewa.secure_element.applet.AppletConstants.nonceTag

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

    fun createGetPublicKey(keyId: ByteArray): ByteArray {
        val begin = byteArrayOf(
            AppletConstants.cla,
            AppletConstants.insGetPublicKey,
            AppletConstants.p1,
            AppletConstants.p2
        )

        return concat(
            begin,
            intToBytes(keyId.size),
            keyId,
            byteArrayOf(maximumLe)
        )
    }

    fun createSignWithKey(ins: Byte, data: ByteArray, splitted: Boolean = false): ByteArray {
        val begin = byteArrayOf(
            if (splitted) AppletConstants.claChained else AppletConstants.cla,
            ins,
            AppletConstants.p1,
            AppletConstants.p2
        )

        val bytesLengthCommand = intToBytes(data.size)
        val extendedLengthData = data.isExtendedLengthData()

        return concat(
            begin,
            if (extendedLengthData) elLengthCommandBuilder(bytesLengthCommand) else bytesLengthCommand,
            data,
            if (extendedLengthData) elLengthExpectedBuilder(byteArrayOf(maximumLe)) else byteArrayOf(maximumLe)
        )
    }

    fun createPopAndAttestation(keyId: ByteArray, nonce: ByteArray): ByteArray {
        val begin = byteArrayOf(
            AppletConstants.cla,
            AppletConstants.insWalletAttestation,
            AppletConstants.p1,
            AppletConstants.p2
        )

        val keyIdPart = concat(intToBytes(keyidTag), byteArrayOf(0x00), intToBytes(keyId.size), keyId)
        val noncePart = concat(intToBytes(nonceTag), byteArrayOf(0x00), intToBytes(nonce.size), nonce)

        val body = concat(keyIdPart, noncePart)
        val bytesLengthCommand = intToBytes(body.size)

        return concat(
            begin,
            bytesLengthCommand,
            body,
            byteArrayOf(maximumLe)
        )
    }

    fun createKeyPair(): ByteArray =
        byteArrayOf(
            AppletConstants.cla,
            AppletConstants.insCreateKeyPair,
            AppletConstants.p1,
            AppletConstants.p2,
            maximumLe
        )

    fun deleteKeyId(keyId: ByteArray): ByteArray {
        val begin = byteArrayOf(
            AppletConstants.cla,
            AppletConstants.insDeleteKeyId,
            AppletConstants.p1,
            AppletConstants.p2
        )

        return concat(
            begin,
            intToBytes(keyId.size),
            keyId,
            byteArrayOf(maximumLe)
        )
    }


    fun createPersonalData(keyId: ByteArray, personalData: ByteArray): ByteArray {
        val begin = byteArrayOf(
            AppletConstants.cla,
            AppletConstants.insStorePersonalData,
            AppletConstants.p1,
            AppletConstants.p2
        )

        val keyIdPart = concat(intToBytes(keyidTag), byteArrayOf(0x00), intToBytes(keyId.size), keyId)
        val body = concat(keyIdPart, personalData)
        val bytesLengthCommand = intToBytes(body.size)
        val extendedLengthData = body.isExtendedLengthData()

        return concat(
            begin,
            if (extendedLengthData) elLengthCommandBuilder(bytesLengthCommand) else bytesLengthCommand,
            body,
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
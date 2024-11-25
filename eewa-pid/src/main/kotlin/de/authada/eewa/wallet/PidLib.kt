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

package de.authada.eewa.wallet

import android.util.Log
import com.google.gson.JsonParser
import de.authada.eewa.secure_element.NoResponseException
import de.authada.eewa.secure_element.SecureElementClosedException
import de.authada.eewa.secure_element.SecureElementWrapper
import de.authada.eewa.secure_element.Util.concat
import de.authada.eewa.secure_element.Util.intToBytes
import de.authada.eewa.secure_element.applet.AppletConstants
import de.authada.eewa.secure_element.applet.AppletConstants.SW_NO_DATA_STORED
import de.authada.eewa.secure_element.applet.AppletConstants.SW_PIN_ONE_TRY_LEFT
import de.authada.eewa.secure_element.applet.AppletConstants.SW_PIN_TWO_TRIES_LEFT
import de.authada.eewa.secure_element.applet.AppletConstants.SW_SUCCESS
import de.authada.eewa.secure_element.applet.AppletConstants.SW_WALLET_BLOCKED
import de.authada.eewa.secure_element.applet.AppletConstants.keyidTag
import de.authada.eewa.secure_element.applet.AppletConstants.signatureDataTag
import de.authada.eewa.secure_element.applet.CommandBuilder
import de.authada.eewa.secure_element.toHexString
import org.bouncycastle.jce.interfaces.ECPublicKey
import java.nio.ByteBuffer
import java.security.PublicKey
import java.time.Instant


class PidLib(private val secureElementWrapper: SecureElementWrapper) {
    companion object {
        private const val pinSize: Int = 6
        private const val tag: String = "WALLETLOG"
        private const val maxSignatureDataSize: Int = 3072

        private val commandBuilder = CommandBuilder()

        private val sdjwtAddressAttributeList = listOf(
            SDJWTFieldName.noPlaceInfo.fieldName,
            SDJWTFieldName.freeTextPlace.fieldName,
            SDJWTFieldName.streetAddress.fieldName,
            SDJWTFieldName.locality.fieldName,
            SDJWTFieldName.postalCode.fieldName,
            SDJWTFieldName.country.fieldName
        )

        private val sdjwtPobAttributeList = listOf(
            SDJWTFieldName.placeOfBirthNoPlaceInfo.fieldName,
            SDJWTFieldName.placeOfBirthFreeTextPlace.fieldName,
            SDJWTFieldName.placeOfBirthLocality.fieldName,
            SDJWTFieldName.placeOfBirthCountry.fieldName
        )
    }

    @Throws(SecureElementClosedException::class)
    fun unlockViaPin(pin: IntArray): PinCheckResponse {
        val name = "UnlockWithPin"
        if (pin.size != pinSize) throw IllegalArgumentException("PIN SIZE WRONG")
        val createVerifyPin = commandBuilder.createVerifyPin(pin)

        return when (val response = secureElementWrapper.transmit(createVerifyPin, name)) {
            SW_PIN_TWO_TRIES_LEFT -> PinCheckResponse.PIN_WRONG_TWO_TRIES_LEFT
            SW_PIN_ONE_TRY_LEFT -> PinCheckResponse.PIN_WRONG_ONE_TRY_LEFT
            SW_WALLET_BLOCKED -> PinCheckResponse.SW_WALLET_BLOCKED
            SW_SUCCESS -> PinCheckResponse.SUCCESSFUL
            else -> {
                Log.d(tag, response)
                throw NoResponseException(name)
            }
        }
    }

    fun onDestroy() {
        secureElementWrapper.closeChannel()
        secureElementWrapper.freeResources()
    }


    @Throws(SecureElementClosedException::class)
    private fun deleteObjects(): ByteArray {
        val name = "ObjectDeletion"
        val createObjectDeletion = commandBuilder.createObjectDeletion()
        val response = secureElementWrapper.pureTransmit(createObjectDeletion, name)
        return responseOrThrow(response, name)
    }


    @Throws(NoResponseException::class)
    private fun responseOrThrow(response: ByteArray, call: String): ByteArray {
        if (response.isEmpty()) {
            throw NoResponseException("Request for $call wasn't Answered")
        }
        return if (response.toHexString().endsWith(SW_SUCCESS) && response.size > 4) {
            response.copyOfRange(0, response.size - 2)
        } else {
            response
        }
    }

    @Throws(NoResponseException::class)
    private fun responseOrThrow(response: String, call: String): String {
        if (response.isEmpty()) {
            throw NoResponseException("Request for $call wasn't Answered")
        }
        return if (response.endsWith(SW_SUCCESS)) {
            response.removeSuffix(SW_SUCCESS)
        } else {
            response
        }
    }

    fun setPin(pin: IntArray): Boolean {
        val name = "setPin"
        val setPinCommand = commandBuilder.createSetPinCommand(pin)
        val response = secureElementWrapper.transmit(setPinCommand, name)
        return (responseOrThrow(response, name).isEmpty())
    }


    private fun getAuthenticationPublicKey(): ECPublicKey {
        val name = "getAuthenticationPublicKey"
        val getAuthPkCommand = commandBuilder.createGetAuthenticationPK()
        var authenticationPublicKeyBytArray =
            secureElementWrapper.pureTransmit(getAuthPkCommand, name)

        authenticationPublicKeyBytArray = responseOrThrow(authenticationPublicKeyBytArray, name)

        Log.d(tag, "AuthPKHex " + authenticationPublicKeyBytArray.toHexString())

        val ecPublicKey = EcPublicKeyPrime256V1Creator.fromHexW(authenticationPublicKeyBytArray)
        return ecPublicKey
    }

    private fun getPublicKeyHex(keyId: ByteArray): ByteArray {
        val name = "getPublicKey"
        val getDevicePkCommand = commandBuilder.createGetPublicKey(keyId)
        var devicePublicKeyBytArray = secureElementWrapper.pureTransmit(getDevicePkCommand, name)

        return responseOrThrow(devicePublicKeyBytArray, name)
    }

    fun getPublicKey(keyId: ByteArray): ECPublicKey {
        val publicKeyHex = getPublicKeyHex(keyId)

        Log.d(tag, "PKHex " + publicKeyHex.toHexString())

        return EcPublicKeyPrime256V1Creator.fromHexW(publicKeyHex)
    }

    fun signWithKey(keyId: ByteArray, dataToSign: ByteArray): ByteArray {
        val name = "signWithKey"

        val keyIdPart = concat(intToBytes( keyidTag), byteArrayOf(0x00), intToBytes(keyId.size), keyId)
        val dataToSignPart = intToBytes(signatureDataTag)
        val fixedSize = keyIdPart.size + dataToSignPart.size + 2

        val dataList = mutableListOf<ByteArray>()

        if (dataToSign.size + fixedSize > maxSignatureDataSize) {
            val numberOfParts = (dataToSign.size + fixedSize) / maxSignatureDataSize

            var fromIndex = 0
            var toIndex = maxSignatureDataSize - fixedSize
            for (i in 0 .. numberOfParts) {
                val rangedData = dataToSign.copyOfRange(fromIndex, toIndex)
                if (i == 0) {
                    val data = concat(keyIdPart, dataToSignPart, intToBytes(rangedData.size), rangedData)
                    dataList.add(i, data)
                } else {
                    dataList.add(i, rangedData)
                }
                if (i != numberOfParts) {
                    fromIndex = toIndex
                    toIndex = if (dataToSign.size - ((i + 1) * maxSignatureDataSize) > maxSignatureDataSize) {
                        toIndex + maxSignatureDataSize
                    } else {
                        toIndex + (dataToSign.size - ((i + 1) * maxSignatureDataSize)) + fixedSize
                    }
                }
            }
        } else {
            var lengthOfData = intToBytes(dataToSign.size)
            if (lengthOfData.size == 1) {
                lengthOfData = byteArrayOf(0x00.toByte(), lengthOfData[0])
            }
            val data = concat(keyIdPart, dataToSignPart, lengthOfData, dataToSign)
            val command = commandBuilder.createSignWithKey(AppletConstants.insCreateSignatureWithKeySingle, data)
            val response = secureElementWrapper.pureTransmit(command, name)
            return responseOrThrow(response, name)
        }

        dataList.forEachIndexed { index, bytes ->
            val command = commandBuilder.createSignWithKey(AppletConstants.insCreateSignatureWithKey, bytes, index != dataList.size - 1)
            val response = secureElementWrapper.pureTransmit(command, name)
            val responseOrThrow = responseOrThrow(response, name)
            if (index == dataList.size - 1) {
                return responseOrThrow
            }
        }

        return byteArrayOf()
    }

    private fun getPoPAndWalletAttestation(
        authenticationCcPublicKey: ECPublicKey,
        keyId: ByteArray,
        nonce: ByteArray
    ): DeviceKeyAttestation {
        val name = "getPopWalletAttestation"

        val getPopWalletAttestation = commandBuilder.createPopAndAttestation(keyId, nonce)
        val response = secureElementWrapper.pureTransmit(getPopWalletAttestation, name)

        val lengthOfProofOfPossession = Integer.decode(
            "0x${
                byteArrayOf(
                    response[0], response[1]
                ).toHexString()
            }"
        )
        Log.d(tag, "lengthOfProofOfPossession $lengthOfProofOfPossession")
        val proofOfPossession = response.copyOfRange(2, lengthOfProofOfPossession + 2)

        Log.d(tag, "proofOfPossession ${proofOfPossession.toHexString()}")


        val positionOfLengthOfKeyAttestation = lengthOfProofOfPossession + 2

        val lengthOfKeyAttestation = Integer.decode(
            "0x${
                byteArrayOf(
                    response[positionOfLengthOfKeyAttestation],
                    response[positionOfLengthOfKeyAttestation + 1]
                ).toHexString()
            }"
        )

        Log.d(tag, "lengthOfKeyAttestation $lengthOfKeyAttestation")

        val walletAttestation = response.copyOfRange(
            positionOfLengthOfKeyAttestation + 2,
            positionOfLengthOfKeyAttestation + 2 + lengthOfKeyAttestation
        )

        Log.d(tag, "walletAttestation ${walletAttestation.toHexString()}")

        val publicKeyByteArray = getPublicKeyHex(keyId)
        Log.d(
            tag, "PKHex " + publicKeyByteArray.toHexString()
        )

        val ecPublicKey = EcPublicKeyPrime256V1Creator.fromHexW(publicKeyByteArray)

        val ellipticCurve256Verify = SignatureChecker.ellipticCurve256Verify(
            ecPublicKey, nonce, proofOfPossession
        )
        Log.d(tag, "verified?: $ellipticCurve256Verify")

        val ellipticCurve256VerifyForWA = SignatureChecker.ellipticCurve256Verify(
            authenticationCcPublicKey, publicKeyByteArray, walletAttestation
        )
        Log.d(tag, "verified?: $ellipticCurve256VerifyForWA")

        deleteObjects()

        return DeviceKeyAttestation(
            ecPublicKey,
            keyId,
            authenticationCcPublicKey,
            walletAttestation,
            proofOfPossession,
        )
    }

    fun walletAttestation(nonce: ByteArray): DeviceKeyAttestation {
        val authenticationPublicKey = getAuthenticationPublicKey()

        val keyId = createKeyPair()
        return getPoPAndWalletAttestation(authenticationPublicKey, keyId, nonce)
    }

    fun createKeyPair(): ByteArray {
        val name = "createKeyPair"

        val createKeyPairCommand = commandBuilder.createKeyPair()
        val pureTransmit = secureElementWrapper.pureTransmit(createKeyPairCommand, name)
        return responseOrThrow(pureTransmit, name)
    }

    fun deleteKeyId(keyId: ByteArray) {
        val name = "deleteKeyId"

        val deleteKeyIdCommand = commandBuilder.deleteKeyId(keyId)
        val pureTransmit = secureElementWrapper.pureTransmit(deleteKeyIdCommand, name)
        Log.d(tag, pureTransmit.toHexString())
    }

    private fun removeStartingZeros(byteArray: ByteArray): ByteArray {
        if (byteArray.toHexString().startsWith("00")) {
            return byteArray.copyOfRange(1, byteArray.size)
        }
        return byteArray
    }

    fun storePersonalData(keyId: ByteArray, personalData: ByteArray): ByteArray {
        val storeDataInApplet = storeDataInApplet(keyId, personalData)
        deleteObjects()

        return storeDataInApplet
    }

    private fun storeDataInApplet(keyId: ByteArray, personalData: ByteArray): ByteArray {
        val name = "storePersonalData"

        val createHmac = commandBuilder.createPersonalData(keyId, personalData)
        val pureTransmit = secureElementWrapper.pureTransmit(createHmac, name)

        return responseOrThrow(pureTransmit, name)
    }

    fun isPinSet(): Boolean {
        val name = "createHasPin"

        val createPin = commandBuilder.createHasPin()
        val pureTransmit = secureElementWrapper.transmit(createPin, name)

        val response = responseOrThrow(pureTransmit, name)
        return (response.isEmpty())
    }

    fun deletePersonalData(): ByteArray {
        val name = "deletePersonalData"

        val createCleanUp = commandBuilder.createCleanUp()
        val pureTransmit = secureElementWrapper.pureTransmit(createCleanUp, name)
        return responseOrThrow(pureTransmit, name)
    }

    fun createPid(
        publicKey: PublicKey,
        cr: ByteArray,
        nonce: ByteArray,
        auditor: String,
        selector: List<String>
    ): Pid {
        deleteObjects()
        val response = createPidInApplet(publicKey, cr, nonce, auditor, getSelectorList(selector))
        deleteObjects()
        return Pid(response)
    }

    private fun createPidInApplet(
        publicKey: PublicKey,
        cr: ByteArray,
        nonce: ByteArray,
        auditor: String,
        selector: List<PersonalData>
    ): ByteArray {
        val w = (publicKey as java.security.interfaces.ECPublicKey).w
        val xByteArray = removeStartingZeros(w.affineX.toByteArray())
        val yByteArray = removeStartingZeros(w.affineY.toByteArray())

        val name = "createPid"


        val iatByteArray = Instant.now().epochSecond.toString().toByteArray(Charsets.UTF_8)
        val auditorByteArray = auditor.toByteArray()

        val createPid = commandBuilder.createPid(
            xByteArray,
            yByteArray,
            cr,
            iatByteArray,
            auditorByteArray,
            nonce,
            let {
                val buffer = ByteBuffer.allocate(selector.size * Short.SIZE_BYTES)
                selector.sortedBy { it.tag }.map { buffer.putShort(it.tag.toShort()) }
                buffer.array()
            }
        )
        val pureTransmit = secureElementWrapper.pureTransmit(createPid, name)
        return responseOrThrow(pureTransmit, name)
    }

    private fun getSelectorList(selector: List<String>): List<PersonalData> =
        selector.flatMap { s ->
            PersonalData.entries.filter {
                if (s != "address" && s != "place_of_birth") {
                    it.attributeName.contentEquals(
                        s, true
                    )
                } else {
                    s == "address" && it.attributeName.startsWith("address.")
                            || s == "place_of_birth" && it.attributeName.startsWith("place_of_birth.")
                }
            }
        }

    fun getPersonalData(cr: ByteArray): Map<String, ByteArray>? {
        val name = "getPersonalData"

        val getPersonalDataCommand = commandBuilder.getPersonalData(cr)
        val pureTransmit = secureElementWrapper.pureTransmit(getPersonalDataCommand, name)
        return try {
            val response = responseOrThrow(pureTransmit, name)
            if (response.isNotEmpty() && response.toHexString() != SW_NO_DATA_STORED) getPersonalDataMap(
                response
            ) else null
        } catch (e: Exception) {
            Log.d(tag, "Error fetching personal data for credential: ${e.message}")
            null
        }
    }

    private fun getPersonalDataMap(rawPersonalData: ByteArray): Map<String, ByteArray>? = try {
        val byteBuffer = ByteBuffer.wrap(rawPersonalData)
        val map = buildMap {
            while (byteBuffer.remaining() > 0) {
                val tag = byteBuffer.getShort().toUShort().toInt()
                val length = byteBuffer.getShort().toUShort().toInt()

                val value = ByteArray(length)
                byteBuffer.get(value)
                PersonalData.entries.find {
                    it.tag == tag
                }?.let {
                    this.put(it.attributeName, it.converter(value))
                }
            }
        }.toMutableMap()

        if (map.keys.any { it in sdjwtAddressAttributeList }) {

            val country = map[SDJWTFieldName.country.fieldName]?.let { convert(it) }
            val locality = map[SDJWTFieldName.locality.fieldName]?.let { convert(it) }
            val postalCode = map[SDJWTFieldName.postalCode.fieldName]?.let { convert(it) }
            val streetAddress = map[SDJWTFieldName.streetAddress.fieldName]?.let { convert(it) }

            val formatted = "{\"country\":\"${country}\", \"locality\":\"${locality}\", \"postal_code\":\"${postalCode}\", \"street_address\":\"${streetAddress}\"}"

            map["address"] = formatted.toByteArray(Charsets.UTF_8)
            map.remove(PersonalData.streetAddress.attributeName)
            map.remove(PersonalData.locality.attributeName)
            map.remove(PersonalData.postalCode.attributeName)
            map.remove(PersonalData.country.attributeName)
        }

        if (map.keys.any { it in sdjwtPobAttributeList }) {
            val locality = map[SDJWTFieldName.placeOfBirthFreeTextPlace.fieldName]?.let { convert(it) } ?: map[SDJWTFieldName.placeOfBirthLocality.fieldName]?.let { convert(it) }
            val country = map[SDJWTFieldName.placeOfBirthCountry.fieldName]?.let { convert(it) }

            val formatted = "{\"locality\":\"${locality}\"${country?.let { "\"country\":\${country}\" }" } ?: ""}}"

            map["place_of_birth"] = formatted.toByteArray(Charsets.UTF_8)
            map.remove(PersonalData.placeOfBirthLocality.attributeName)
            map.remove(PersonalData.placeOfBirthCountry.attributeName)
        }

        map["issuing_country"] = "D".toByteArray(Charsets.UTF_8)
        map["issuing_authority"] = "D".toByteArray(Charsets.UTF_8)

        map
    } catch (e: Exception) {
        Log.d(tag, "Error parsing raw personal data to map: ${e.message}")
        null
    }

    private fun convert(data: ByteArray): String =
        JsonParser.parseString(data.decodeToString()).asString

}
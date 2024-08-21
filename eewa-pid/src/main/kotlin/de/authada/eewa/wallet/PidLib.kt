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
import de.authada.eewa.secure_element.NoResponseException
import de.authada.eewa.secure_element.SecureElementClosedException
import de.authada.eewa.secure_element.SecureElementWrapper
import de.authada.eewa.secure_element.applet.AppletConstants.SW_NO_DATA_STORED
import de.authada.eewa.secure_element.applet.AppletConstants.SW_PIN_ONE_TRY_LEFT
import de.authada.eewa.secure_element.applet.AppletConstants.SW_PIN_TWO_TRIES_LEFT
import de.authada.eewa.secure_element.applet.AppletConstants.SW_SUCCESS
import de.authada.eewa.secure_element.applet.AppletConstants.SW_WALLET_BLOCKED
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

    private fun getDevicePublicKeyHex(): ByteArray {
        val name = "getDevicePublicKey"
        val getDevicePkCommand = commandBuilder.createGetDevicePK()
        var devicePublicKeyBytArray = secureElementWrapper.pureTransmit(getDevicePkCommand, name)

        return responseOrThrow(devicePublicKeyBytArray, name)
    }

    fun getDevicePublicKey(): ECPublicKey {
        val devicePublicKeyHex = getDevicePublicKeyHex()

        Log.d(tag, "devicePKHex " + devicePublicKeyHex.toHexString())

        return EcPublicKeyPrime256V1Creator.fromHexW(devicePublicKeyHex)
    }

    fun signWithDevKey(nonce: ByteArray): ByteArray {
        val name = "signWithDevKey"

        val dataList = mutableListOf<ByteArray>()

        if (nonce.size > maxSignatureDataSize) {
            val numberOfParts = nonce.size / maxSignatureDataSize
            var fromIndex = 0
            var toIndex = maxSignatureDataSize
            for (i in 0 .. numberOfParts) {
                dataList.add(i, nonce.copyOfRange(fromIndex, toIndex))
                if (i != numberOfParts) {
                    fromIndex = toIndex
                    toIndex = if (nonce.size - ((i + 1) * maxSignatureDataSize) > maxSignatureDataSize) {
                        toIndex + maxSignatureDataSize
                    } else {
                        toIndex + (nonce.size - ((i + 1) * maxSignatureDataSize))
                    }
                }
            }
        } else {
            dataList.add(nonce)
        }

        dataList.forEachIndexed { index, bytes ->
            val command = commandBuilder.createSignWithDevKey(bytes, index != dataList.size - 1)
            val response = secureElementWrapper.pureTransmit(command, name)
            val responseOrThrow = responseOrThrow(response, name)
            if (index == dataList.size - 1) {
                return responseOrThrow
            }
        }

        return byteArrayOf()
    }

    private fun getPoPAndWalletAttestation(
        authenticationCcPublicKey: ECPublicKey, nonce: ByteArray
    ): DeviceKeyAttestation {
        val name = "getPopWalletAttestation"

        val getPopWalletAttestation = commandBuilder.createPopAndAttestation(nonce)
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

        val devicePublicKeyByteArray = getDevicePublicKeyHex()
        Log.d(
            tag, "devicePKHex " + devicePublicKeyByteArray.toHexString()
        )

        val ecDevicePublicKey = EcPublicKeyPrime256V1Creator.fromHexW(devicePublicKeyByteArray)

        val ellipticCurve256Verify = SignatureChecker.ellipticCurve256Verify(
            ecDevicePublicKey, nonce, proofOfPossession
        )
        Log.d(tag, "verified?: $ellipticCurve256Verify")

        val ellipticCurve256VerifyForWA = SignatureChecker.ellipticCurve256Verify(
            authenticationCcPublicKey, devicePublicKeyByteArray, walletAttestation
        )
        Log.d(tag, "verified?: $ellipticCurve256VerifyForWA")

        deleteObjects()

        return DeviceKeyAttestation(
            ecDevicePublicKey,
            authenticationCcPublicKey,
            walletAttestation,
            proofOfPossession,
        )
    }

    fun walletAttestation(nonce: ByteArray): DeviceKeyAttestation {
        val authenticationPublicKey = getAuthenticationPublicKey()
        return getPoPAndWalletAttestation(authenticationPublicKey, nonce)
    }

    private fun removeStartingZeros(byteArray: ByteArray): ByteArray {
        if (byteArray.toHexString().startsWith("00")) {
            return byteArray.copyOfRange(1, byteArray.size)
        }
        return byteArray
    }

    fun storePersonalData(personalData: ByteArray): ByteArray {
        val storeDataInApplet = storeDataInApplet(personalData)
        deleteObjects()

        return storeDataInApplet
    }

    private fun storeDataInApplet(personalData: ByteArray): ByteArray {
        val name = "storePersonalData"

        val createHmac = commandBuilder.createPersonalData(personalData)
        val pureTransmit = secureElementWrapper.pureTransmit(createHmac, name)

        return responseOrThrow(pureTransmit, name)
    }

    fun isPinSet(): Boolean {
        val name = "createHasPin"

        val createHmac = commandBuilder.createHasPin()
        val pureTransmit = secureElementWrapper.transmit(createHmac, name)

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
        selector: List<PersonalData>
    ): Pid {
        deleteObjects()
        val response = createPidInApplet(publicKey, cr, nonce, auditor, selector)
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
        buildMap {
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
        }
    } catch (e: Exception) {
        Log.d(tag, "Error parsing raw personal data to map: ${e.message}")
        null
    }

}
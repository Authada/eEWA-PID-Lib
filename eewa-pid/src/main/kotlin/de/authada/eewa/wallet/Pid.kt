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
import de.authada.eewa.secure_element.Util.concat
import de.authada.eewa.secure_element.toHexString
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class Pid(pidBase64UrlEncoded: ByteArray) {

    private var signature: ByteArray = byteArrayOf()
    private var subject: ByteArray = byteArrayOf()
    private val tag = "PidCreator"
    private var header: ByteArray = byteArrayOf()
    private var body: ByteArray = byteArrayOf()

    private var kbJwtSubject = byteArrayOf()
    private var kbJwtSignature = byteArrayOf()

    private var kbHeader: ByteArray = byteArrayOf()
    private var kbBody: ByteArray = byteArrayOf()
    private val sdJWT: String

    val pidString = String(pidBase64UrlEncoded)

    init {
        val split = pidString.split('~')

        createSdJwt(split[0])
        sdJWT = split[0] + "~"

        createKbJwt(split[1])
    }

    private fun createKbJwt(kbJwtBase64UrlEncoded: String) {
        val kbJwtByteArray = kbJwtBase64UrlEncoded.split('.')

        kbJwtSubject = (kbJwtByteArray[0] + '.' + kbJwtByteArray[1]).toByteArray()

        kbJwtSignature = Base64.getUrlDecoder().decode(
            String(kbJwtByteArray[2].toByteArray())
        )

        kbHeader =
            Base64.getUrlDecoder().decode(kbJwtByteArray[0])

        kbBody =
            Base64.getUrlDecoder().decode(kbJwtByteArray[1])
    }

    private fun createSdJwt(sdJwtBase64UrlEncoded: String) {
        val sdJwtArray = sdJwtBase64UrlEncoded.split('.')

        subject = (sdJwtArray[0] + '.' + sdJwtArray[1]).toByteArray()

        signature = Base64.getUrlDecoder().decode(sdJwtArray[2])

        header =
            Base64.getUrlDecoder().decode(sdJwtArray[0])

        body =
            Base64.getUrlDecoder().decode(sdJwtArray[1])
    }

    fun print() {
        Log.d(tag, "jwt subject as Hex " + subject.toHexString())
        Log.d(tag, "jwt base64DecodedSignature " + signature.toHexString())
        Log.d("pid", "jwt header " + String(header))
        Log.d("pid", "jwt body " + String(body))

        Log.d(tag, "kb subject as Hex " + kbJwtSubject.toHexString())
        Log.d(tag, "kb base64DecodedSignature " + kbJwtSignature.toHexString())
        Log.d("pid", "kb header " + String(kbHeader))
        Log.d("pid", "kb body " + String(kbBody))
    }

    fun verifyHmac(sharedSecret: ByteArray): Boolean {
        val algorithm = "HmacSHA256"
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(sharedSecret, algorithm))
        val createdSignature = mac.doFinal(subject)
        Log.d(tag, "Created Signature " + createdSignature.toHexString())
        return signature.contentEquals(createdSignature)
    }

    fun verifyKeyBinding(): Boolean {
        val ephemeralPublicKey = getEphemeralPublicKey()
        return SignatureChecker.ellipticCurve256Verify(
            ephemeralPublicKey,
            kbJwtSubject,
            kbJwtSignature
        )
    }

    private fun getEphemeralPublicKey(): org.bouncycastle.jce.interfaces.ECPublicKey {
        val headerJson = JSONObject(String(body))
        val jwk = headerJson.getJSONObject("cnf").getJSONObject("jwk")
        val publicKeyX = Base64.getUrlDecoder().decode(jwk.getString("x"))
        val publicKeyY = Base64.getUrlDecoder().decode(jwk.getString("y"))

        val foreignPublicKey = concat(
            byteArrayOf(0x04.toByte()), publicKeyX, publicKeyY
        )

        return EcPublicKeyPrime256V1Creator.fromHexW(foreignPublicKey)
    }

    fun validateHash(): Boolean {
        val sdJwtByteArray = sdJWT.toByteArray()

        val digest = MessageDigest.getInstance("SHA-256")
        val sha256Hash = digest.digest(sdJwtByteArray)
        val sdHashFromApplet = JSONObject(String(kbBody)).getString("sd_hash")
        Log.d(tag, "Generated Hash ${sha256Hash.toHexString()}")
        val decodedSha256Applet = Base64.getUrlDecoder().decode(sdHashFromApplet)
        Log.d(tag, "Applet Hash ${decodedSha256Applet.toHexString()}")
        return decodedSha256Applet.equals(sha256Hash)
    }
}

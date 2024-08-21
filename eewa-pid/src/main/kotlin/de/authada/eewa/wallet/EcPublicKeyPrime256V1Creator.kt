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

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.ECPointUtil
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import java.security.KeyFactory
import java.security.spec.ECPublicKeySpec

class EcPublicKeyPrime256V1Creator {
    companion object {
        fun fromHexW(w: ByteArray): ECPublicKey {
            val spec = ECNamedCurveTable.getParameterSpec("prime256v1")
            val kf = KeyFactory.getInstance("ECDSA", BouncyCastleProvider())
            val params = ECNamedCurveSpec("prime256v1", spec.curve, spec.g, spec.n)
            val point = ECPointUtil.decodePoint(params.curve, w)
            val pubKeySpec = ECPublicKeySpec(point, params)
            return kf.generatePublic(pubKeySpec) as ECPublicKey
        }
    }
}
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

import com.google.gson.JsonPrimitive

enum class PersonalData(
    val tag: Int,
    val attributeName: String,
    val converter: (ByteArray) -> ByteArray
) {
    givenName(0xC001, SDJWTFieldName.givenName.fieldName, ::string),
    familyName(0xC002, SDJWTFieldName.familyName.fieldName, ::string),
    birthDate(0xC003, SDJWTFieldName.birthDate.fieldName, ::string),
    sourceDocumentType(0xC004, SDJWTFieldName.sourceDocumentType.fieldName, ::string),
    dateOfExpiry(0xC005, SDJWTFieldName.dateOfExpiry.fieldName, ::string),
    academicTitle(0xC006, SDJWTFieldName.academicTitle.fieldName, ::string),
    streetAddress(0xC007, SDJWTFieldName.streetAddress.fieldName, ::string),
    locality(0xC008, SDJWTFieldName.locality.fieldName, ::string),
    postalCode(0xC009, SDJWTFieldName.postalCode.fieldName, ::string),
    country(0xC00A, SDJWTFieldName.country.fieldName, ::string),
    nationality(0xC00D, SDJWTFieldName.nationality.fieldName, ::string),
    birthFamilyName(0xC00E, SDJWTFieldName.birthFamilyName.fieldName, ::string),
    placeOfBirthLocality(0xC00F, SDJWTFieldName.placeOfBirthLocality.fieldName, ::string),
    placeOfBirthCountry(0xC010, SDJWTFieldName.placeOfBirthCountry.fieldName, ::string),
    alsoKnownAs(0xC013, SDJWTFieldName.alsoKnownAs.fieldName, ::string);
}
fun string(data: ByteArray): ByteArray = JsonPrimitive(data.toString(Charsets.UTF_8)).toString().toByteArray(Charsets.UTF_8)
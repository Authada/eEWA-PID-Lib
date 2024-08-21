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
    givenName(0xC001, "given_name", ::string),
    familyName(0xC002, "family_name", ::string),
    birthDate(0xC003, "birth_date", ::string),
    sourceDocumentType(0xC004, "source_document_type", ::string),
    dateOfExpiry(0xC005, "expiry_date", ::string),
    academicTitle(0xC006, "academic_title", ::string),
    streetAddress(0xC007, "resident_street", ::string),
    locality(0xC008, "resident_city", ::string),
    postalCode(0xC009, "resident_postal_code", ::string),
    country(0xC00A, "resident_country", ::string),
    noPlaceInfo(0xC00B, "resident_address", ::string),
    freeTextPlace(0xC00C, "resident_address", ::string),
    nationality(0xC00D, "nationality", ::string),
    birthFamilyName(0xC00E, "family_name_birth", ::string),
    placeOfBirthLocality(0xC00F, "birth_city", ::string),
    placeOfBirthCountry(0xC010, "birth_country", ::string),
    placeOfBirthNoPlaceInfo(0xC011, "birth_address", ::string),
    placeOfBirthFreeTextPlace(0xC012, "birth_address", ::string),
    alsoKnownAs(0xC013, "also_known_as", ::string);

}
fun string(data: ByteArray): ByteArray = JsonPrimitive(data.toString(Charsets.UTF_8)).toString().toByteArray(Charsets.UTF_8)
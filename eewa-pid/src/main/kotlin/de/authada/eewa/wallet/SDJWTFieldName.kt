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

enum class SDJWTFieldName(val fieldName: String) {
    givenName("given_name"),
    familyName("family_name"),
    birthDate("birthdate"),
    sourceDocumentType("source_document_type"),
    dateOfExpiry("exp"),
    academicTitle("academic_title"),
    streetAddress("address.street_address"),
    locality("address.locality"),
    postalCode("address.postal_code"),
    country("address.country"),
    noPlaceInfo("address.no_place_info"),
    freeTextPlace("address.free_text_place"),
    nationality("nationalities"),
    birthFamilyName("birth_family_name"),
    placeOfBirthLocality("place_of_birth.locality"),
    placeOfBirthCountry("place_of_birth.country"),
    placeOfBirthNoPlaceInfo("place_of_birth.no_place_info"),
    placeOfBirthFreeTextPlace("place_of_birth.free_text_place"),
    alsoKnownAs("also_known_as")
}
package nty.example.hybridencryptionkotlinexample

import com.fasterxml.jackson.databind.PropertyNamingStrategy
import com.fasterxml.jackson.databind.annotation.JsonNaming
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.nio.charset.StandardCharsets
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

@RestController
@RequestMapping("/hybrid")
class HybridController(val hybridCryptoHelper: HybridCryptoHelper) {

    @PostMapping("/encrypt")
    fun encrypt(@RequestBody request: EncryptRequestModel): EncryptResponseModel {
        return EncryptResponseModel(cipherText = request.plainText,
                cipherKey = request.plainKey)
    }

    @PostMapping("/decrypt")
    fun decrypt(@RequestBody request: DecryptRequestModel): DecryptResponseModel {
        return DecryptResponseModel(plainText = request.cipherText,
                plainKey = request.cipherKey)
    }

}

@Service
class HybridCryptoHelper {

    private val GCM_IV_LENGTH = 12
    private val GCM_TAG_LENGTH = 16


    private fun getAESSecretKeyFromString(encodedKey: String): SecretKey {
        val decodedKey = Base64.getDecoder().decode(encodedKey)
        return SecretKeySpec(decodedKey, 0, decodedKey.size, "AES")
    }


    fun encryptAESGCMToBase64(plaintext: String, key: String): String? {
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = getAESSecretKeyFromString(key)

            val gcmParameterSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, ByteArray(GCM_IV_LENGTH))

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec)
            val cipherText = cipher.doFinal(plaintext.toByteArray())

            return Base64.getEncoder().encodeToString(cipherText)
        } catch (e: Exception) {
            return null
        }

    }

    fun decryptAESGCMFromBase64(cipherText: String, key: String): String? {
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = getAESSecretKeyFromString(key)

            val gcmParameterSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, ByteArray(GCM_IV_LENGTH))

            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec)
            val decryptedText = cipher.doFinal(Base64.getDecoder().decode(cipherText))

            return String(decryptedText, StandardCharsets.UTF_8)
        } catch (e: Exception) {
            return null
        }

    }
}

@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy::class)
data class EncryptRequestModel(val plainText: String? = null,
                               val plainKey: String? = null)

@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy::class)
data class EncryptResponseModel(val cipherText: String? = null,
                                val cipherKey: String? = null)


@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy::class)
data class DecryptRequestModel(val cipherText: String? = null,
                               val cipherKey: String? = null)

@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy::class)
data class DecryptResponseModel(val plainText: String? = null,
                                val plainKey: String? = null)
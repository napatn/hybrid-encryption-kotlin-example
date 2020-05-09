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

enum class Keys(val value: String) {
//    generated using this online tool
//    https://www.devglan.com/online-tools/rsa-encryption-decryption
    RSA_PUBLIC_1024("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCSAsbTSVBfsbWfki1iop2LGCI+70UWaXoWhzcVoazg/jblSx33vxQC4kdPqJ3RugJ+od/bq7M90l7Wm/FGH0LmnOn/awusnDFOQCRG2S60bsqmlmJthvbPXtRaMuf8MLxzEbXvy7+AjG42tIqoEmOHzJexrfBS2NCPACWklTO9bwIDAQAB"),
    RSA_PRIVATE_1024("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJICxtNJUF+xtZ+SLWKinYsYIj7vRRZpehaHNxWhrOD+NuVLHfe/FALiR0+ondG6An6h39ursz3SXtab8UYfQuac6f9rC6ycMU5AJEbZLrRuyqaWYm2G9s9e1Foy5/wwvHMRte/Lv4CMbja0iqgSY4fMl7Gt8FLY0I8AJaSVM71vAgMBAAECgYB5tN7Ol7nrSlI+ZLZ4FVyE6OUC2KcZ+2nNBYChA1b7ZGuVzXt5W0ju7nbKq56Bhy81JvFWRlTuH0D2Wp5O+RflqCTAVTayWPqcwVLgBQNiuJ4bTaTaoVrpaeyEWhQhjxJLIHrasI/bnpPOMvSLnWDHCh8jXNcsZfuxVjpj3kw6gQJBAMmqqTr3eDrhgLXNdX36ASPRK0N3+Oh/Ta5rmA+AdGY7yqOJnXN6zANa1pzX/iag0ASuNWezx33uF5lQdky55zECQQC5WW1sH6Qe0Z9Vl7AVoJj+YPROGP99d+y82MlOMmitmTjnUAQWWWFL4EXfyZ1CUrIuawZjKrZLWDm4xKzm8gafAkARpCk7rExLMlDVFo0RoR4aaQDU3RjcFc7Q1D6wFHeaPd7DIZWxdWuFW5vsioSEEos/7ZFkafiojnxn//7pRVXxAkAmcjBKTz3hzqV4QaCau9dAXKgQUwsb4XZPrcAD4lzoNXIiOOzAHgYakQitZMqj6TdgfX6zrzZk5oYCl3kt5mINAkEAnuk9H2/mLGIIdsZb09FLnHlPljTOCKCM6es72XbELd9hiD/nzu58ho91CJnVK1BD8AlyS9jUqmgTxaSQ8SXqhg=="),
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
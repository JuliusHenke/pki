package rsa

import org.apache.commons.codec.binary.Base64.decodeBase64
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import java.io.FileReader
import java.security.KeyFactory
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

val keyFactoryRSA: KeyFactory = KeyFactory.getInstance("RSA")

fun extractAsymmetricCipherKeyPairRSA(publicKeyFile: String, privateKeyFile: String): AsymmetricCipherKeyPair {
    val publicKey = getPublicRSAKeyFromFile(publicKeyFile)
    val privateKey = getPrivateRSAKeyFromFile(privateKeyFile)
    return AsymmetricCipherKeyPair(
        RSAKeyParameters(false, publicKey.modulus, publicKey.publicExponent),
        RSAKeyParameters(true, privateKey.modulus, privateKey.privateExponent),
    )
}

fun getKeyPairRSAPKCS1FromFile(privateKeyFile: String): KeyPair {
    val pemParser = PEMParser(FileReader(privateKeyFile))
    val converter = JcaPEMKeyConverter().setProvider("BC")
    val pemObject = pemParser.readObject()
    return converter.getKeyPair(pemObject as PEMKeyPair)
}

fun getPublicRSAKeyFromFile(keyFile: String) = keyFactoryRSA.generatePublic(
    X509EncodedKeySpec(extractRSAKeyFromFile(keyFile))
) as RSAPublicKey

fun getPrivateRSAKeyFromFile(keyFile: String) = keyFactoryRSA.generatePrivate(
    PKCS8EncodedKeySpec(extractRSAKeyFromFile(keyFile))
) as RSAPrivateKey

fun extractRSAKeyFromFile(keyFile: String): ByteArray {
    val key = FileReader(keyFile)
        .readText()
        .replace("-----(\\w|\\s)*-----(\\s)*".toRegex(), "")
    return decodeBase64(key)
}
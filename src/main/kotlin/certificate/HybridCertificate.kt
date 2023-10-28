package certificate

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OutputStream
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.HybridCertificateBuilder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import org.bouncycastle.pqc.crypto.qtesla.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate

fun generateKeyPairQTESLA(publicKeyFile: String, privateKeyFile: String): AsymmetricCipherKeyPair {
    val generator = QTESLAKeyPairGenerator()
    val parameters = QTESLAKeyGenerationParameters(QTESLASecurityCategory.PROVABLY_SECURE_I, SecureRandom())
    generator.init(parameters)
    val keyPair = generator.generateKeyPair()
    saveKeyPairQTESLA(keyPair, publicKeyFile, privateKeyFile)
    return keyPair
}

fun saveKeyPairQTESLA(keyPair: AsymmetricCipherKeyPair, publicKeyFile: String, privateKeyFile: String) {
    val publicKey = QTESLAUtils.toASN1Primitive(keyPair.public as QTESLAPublicKeyParameters)
    val privateKey = QTESLAUtils.toASN1Primitive(keyPair.private as QTESLAPrivateKeyParameters)
    ASN1OutputStream(FileOutputStream(publicKeyFile)).writeObject(publicKey)
    ASN1OutputStream(FileOutputStream(privateKeyFile)).writeObject(privateKey)
}

fun readKeyPairQTESLA(publicKeyFile: String, privateKeyFile: String): AsymmetricCipherKeyPair {
    val publicKey = ASN1InputStream(FileInputStream(publicKeyFile)).readObject()
    val privateKey = ASN1InputStream(FileInputStream(privateKeyFile)).readObject()
    return AsymmetricCipherKeyPair(
        QTESLAUtils.fromASN1Primitive(publicKey.encoded),
        QTESLAUtils.fromASN1PrimitivePrivate(privateKey.encoded),
    )
}

fun createCACertificate(
    caPrimary: AsymmetricCipherKeyPair,
    caSecondary: AsymmetricCipherKeyPair,
    x500NameCA: X500Name
): X509Certificate {
    val publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(caPrimary.public)
    val certBuilder = HybridCertificateBuilder(
        x500NameCA,
        BigInteger.valueOf(1),
        yesterdayUTC(),
        oneYearUTC(),
        x500NameCA,
        publicKeyInfo,
        caSecondary.public,
    )
    certBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
    certBuilder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
    certBuilder.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        SubjectKeyIdentifier(publicKeyInfo.getKeyIdentifier())
    )

    return buildHybridCertificate(
        certBuilder,
        caPrimary,
        caSecondary
    )
}

fun createEECertificate(
    eePrimary: AsymmetricCipherKeyPair,
    eeSecondary: AsymmetricCipherKeyPair,
    caPrimary: AsymmetricCipherKeyPair,
    caSecondary: AsymmetricCipherKeyPair,
    x500NameCA: X500Name,
    x500NameEE: X500Name,
    subjectAlternativeName: String,
): X509Certificate {
    val certBuilder = HybridCertificateBuilder(
        x500NameCA,
        BigInteger.valueOf(2),
        yesterdayUTC(),
        oneYearUTC(),
        x500NameEE,
        SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(eePrimary.public),
        eeSecondary.public,
    )
    certBuilder.addExtension(
        Extension.authorityKeyIdentifier,
        false,
        AuthorityKeyIdentifier(
            caPrimary.getSubjectPublicKeyIdentifier(),
            GeneralNames(GeneralName(GeneralName.directoryName, x500NameCA)),
            BigInteger.valueOf(1)
        )
    )
    certBuilder.addExtension(Extension.basicConstraints, false, BasicConstraints(false))
    certBuilder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
    certBuilder.addExtension(
        Extension.subjectAlternativeName,
        false,
        convertAlternativeNameIntoBytes(subjectAlternativeName)
    )

    return buildHybridCertificate(
        certBuilder,
        caPrimary,
        caSecondary
    )
}

fun buildHybridCertificate(
    certBuilder: HybridCertificateBuilder,
    caPrimary: AsymmetricCipherKeyPair,
    caSecondary: AsymmetricCipherKeyPair,
): X509Certificate {
    val sigAlg = DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA")
    val digAlg = DefaultDigestAlgorithmIdentifierFinder().find(sigAlg)
    val primarySigner = BcRSAContentSignerBuilder(sigAlg, digAlg).build(caPrimary.private)
    val secondarySigner = QTESLAContentSigner(caSecondary.private as QTESLAPrivateKeyParameters)

    val certHolder: X509CertificateHolder = certBuilder.buildHybrid(primarySigner, secondarySigner)
    return JcaX509CertificateConverter().getCertificate(certHolder)
}

fun AsymmetricCipherKeyPair.getSubjectPublicKeyIdentifier() =
    SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(this.public).getKeyIdentifier()

fun SubjectPublicKeyInfo.getKeyIdentifier(): ByteArray =
    MessageDigest.getInstance("SHA1").digest(this.publicKeyData.bytes)

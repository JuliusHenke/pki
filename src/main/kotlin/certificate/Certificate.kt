package certificate

import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.RFC4519Style
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory
import java.io.FileWriter
import java.math.BigInteger
import java.security.KeyPair
import java.security.PublicKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*

fun buildX500Name(
    country: String,
    state: String,
    location: String,
    organisation: String,
    organisationalUnit: String,
    issuer: String,
): X500Name {
    val builder = X500NameBuilder(RFC4519Style.INSTANCE)
    builder.addRDN(RFC4519Style.c, country)
    builder.addRDN(RFC4519Style.st, state)
    builder.addRDN(RFC4519Style.l, location)
    builder.addRDN(RFC4519Style.o, organisation)
    builder.addRDN(RFC4519Style.ou, organisationalUnit)
    builder.addRDN(RFC4519Style.cn, issuer)
    return builder.build()
}

fun generateX509Certificate(
    keyPair: KeyPair,
    x500Name: X500Name,
    issuerAlternativeName: String,
): X509Certificate {
    val certificateBuilder: X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
        x500Name,
        BigInteger.valueOf(1),
        yesterdayUTC(),
        oneYearUTC(),
        x500Name,
        keyPair.public
    )
        .addExtension(Extension.basicConstraints, false, BasicConstraints(false))
        .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
        .addExtension(
            Extension.issuerAlternativeName,
            false,
            convertAlternativeNameIntoBytes(issuerAlternativeName)
        )

    val contentSigner: ContentSigner = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
    return JcaX509CertificateConverter().setProvider(BouncyCastleProvider())
        .getCertificate(certificateBuilder.build(contentSigner)).verifyAll(keyPair.public)
}

fun convertAlternativeNameIntoBytes(alternativeName: String): ByteArray =
    DEROctetString(GeneralNames(GeneralName(GeneralName.rfc822Name, alternativeName))).octets

fun saveCertificate(certificate: Certificate, fileLocation: String) {
    val writer = JcaPEMWriter(FileWriter(fileLocation))
    writer.writeObject(certificate)
    writer.close()
}

fun X509Certificate.verifyAll(publicKey: PublicKey): X509Certificate {
    this.checkValidity()
    this.verify(publicKey)
    this.verify(this.publicKey)
    return this
}

fun X509Certificate.getRSAKeyIdentifier(): ByteArray {
    val publicRSAKey = this.publicKey as RSAPublicKey
    val publicRSAKeyParameters = RSAKeyParameters(
        false,
        publicRSAKey.modulus,
        publicRSAKey.publicExponent
    ) as AsymmetricKeyParameter
    return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicRSAKeyParameters).getKeyIdentifier()
}

fun yesterdayUTC(): Date = Date.from(Instant.now().minus(1, ChronoUnit.DAYS))
fun oneYearUTC(): Date = Date.from(Instant.now().plus(1, ChronoUnit.YEARS))
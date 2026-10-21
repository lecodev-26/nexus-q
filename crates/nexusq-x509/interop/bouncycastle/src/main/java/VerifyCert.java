import java.io.FileReader;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;

/** Parse a PEM certificate and verify its signature with the same public key. */
public final class VerifyCert {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Usage: VerifyCert certificate.pem");
        Security.addProvider(new BouncyCastleProvider());
        try (PEMParser parser = new PEMParser(new FileReader(args[0]))) {
            Object object = parser.readObject();
            if (!(object instanceof X509CertificateHolder holder)) {
                throw new IllegalArgumentException("Input is not an X.509 certificate");
            }
            X509Certificate certificate = new JcaX509CertificateConverter()
                    .setProvider("BC").getCertificate(holder);
            certificate.verify(certificate.getPublicKey(), "BC");
            System.out.println("BC_VERIFY_OK version=" + Security.getProvider("BC").getVersionStr()
                    + " sigOID=" + certificate.getSigAlgOID());
        }
    }
}

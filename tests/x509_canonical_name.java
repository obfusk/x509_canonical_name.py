import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class X509CanonicalName {
    public static void main(String[] args) {
        try {
            FileInputStream i = new FileInputStream(args[0]);
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(i);
            String name = cert.getIssuerX500Principal()
                .getName(javax.security.auth.x500.X500Principal.CANONICAL);
            System.out.println(name);
        } catch (ArrayIndexOutOfBoundsException | FileNotFoundException | CertificateException e) {
            System.err.println(e);
        }
    }
}

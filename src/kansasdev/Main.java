package kansasdev;

import net.sf.scuba.smartcards.CardFileInputStream;
import net.sf.scuba.smartcards.CardService;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.jcajce.util.JcaJceUtils;
import org.jmrtd.BACKey;
import org.jmrtd.PassportService;
import org.jmrtd.lds.*;
import org.jmrtd.lds.icao.*;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceInfo;
import org.jmrtd.protocol.EACCAResult;

import javax.imageio.ImageIO;
import javax.security.auth.x500.X500Principal;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.List;
import java.util.*;

public class Main {

    public static void main(String[] args) {
        try {

            String dob = "";
            String doc = "";
            String val = "";

            if(args.length==3)
            {
                String[] docParts = args[0].split(":");
                String[] dobParts = args[1].split(":");
                String[] valParts = args[2].split(":");
                doc = docParts[1];
                dob = dobParts[1];
                val = valParts[1];
            }
            else
            {
                throw new Exception("ERR not enough parameters:\r\nProvide -doc:xyz -dob:yyMMdd -val:yyMMdd");
            }

            CleanOutputDirectory();
            TerminalFactory tf = TerminalFactory.getDefault();
            List<CardTerminal> terminals = tf.terminals().list();
            System.out.println("Readers available:");
            System.out.println(terminals + "\n");
            CardTerminal ct = null;
            int indexer = 0;
            //readers choosen for reading (from config file)
            String reader = ReadConfig("reader");
            if (reader != "")
            {
                for (CardTerminal c : terminals) {
                    String current = c.getName();
                    if (current.equals(reader))
                    {
                        ct = c;
                        break;
                    }
                }
            }
            else
            {
                throw new Exception("No smart card reader in config file or wrong reader name");
            }
            if(ct==null) {
                throw new Exception("No smart card reader name match available readers");
            }

            if(ct.waitForCardPresent(5000)) {

                System.out.println("OK Reader for reading: " + ct.getName());

                CardService cs = CardService.getInstance(ct);

                PassportService passportService = new PassportService(cs,256,224,false,true);
                 passportService.open();
                 System.out.println("OK Session opened");
                //BACKey bacKey = new BACKey("EM6492911", "871118", "280111");
                //BACKey bacKey = new BACKey("DAB351137","810220","290325");
                BACKey bacKey = new BACKey(doc,dob,val);
                boolean paceSucceeded = false;
                String forceBAC = ReadConfig("forcebac");
                if(forceBAC.equals("false")||forceBAC=="")
                {
                    try {
                        CardAccessFile cardAccessFile = new CardAccessFile(passportService.getInputStream(PassportService.EF_CARD_ACCESS));
                        System.out.println("OK Method of access taken");
                        Collection<SecurityInfo> securityInfos = cardAccessFile.getSecurityInfos();
                        SecurityInfo securityInfo = securityInfos.iterator().next();
                        String ProtocolOIDString = securityInfo.getProtocolOIDString();
                        String ObjectIdentifier = securityInfo.getObjectIdentifier();

                        List<PACEInfo> paceInfos = getPACEInfos(securityInfos);

                        if (paceInfos != null && paceInfos.size() > 0) {
                            PACEInfo paceInfo = paceInfos.get(0);

                            passportService.doPACE(bacKey, paceInfo.getObjectIdentifier(), PACEInfo.toParameterSpec(paceInfo.getParameterId()));
                            System.out.println("OK PACE method would be used");
                            paceSucceeded = true;
                        } else {
                            paceSucceeded = false;
                        }
                    }
                    catch(net.sf.scuba.smartcards.CardServiceException cse)
                    {
                        System.out.println("ERR No PACE document probably, trying BAC.."+cse.getMessage());
                        paceSucceeded = false;
                    }
                }
                    passportService.sendSelectApplet(paceSucceeded);
                if(!paceSucceeded) {
                    passportService.doBAC(bacKey);
                    System.out.println("OK BAC method would be used");
                }
                CardFileInputStream cfis = passportService.getInputStream(PassportService.EF_COM);
                System.out.println("OK index of document taken");
                COMFile comPlik = new COMFile(cfis);
                int[] spis = comPlik.getTagList();
                List<Integer> lstSpis = new ArrayList<Integer>();
                for(int s : spis)
                {
                    lstSpis.add(s);
                }

                if(lstSpis.contains(LDSFile.EF_DG1_TAG))
                {
                    CardFileInputStream dg1stream = passportService.getInputStream(PassportService.EF_DG1);
                    Files.write(Paths.get("dg1.bin"),dg1stream.readAllBytes());
                    InputStream is = new BufferedInputStream(new FileInputStream("dg1.bin"));
                    DG1File dg1Plik = new DG1File(is);
                    is.close();

                    MRZInfo mrzClass = dg1Plik.getMRZInfo();
                    String mrz = mrzClass.toString();
                    Files.write(Paths.get("mrz.txt"),mrz.getBytes());
                    String LastName = "Lastname: "+mrzClass.getPrimaryIdentifier();
                    String FirstName = "\r\nFirstname: "+mrzClass.getSecondaryIdentifier();
                    String DOB = "\r\nDateOfBirth: "+mrzClass.getDateOfBirth();
                    String ExpirationDate = "\r\nExpirationDate: "+mrzClass.getDateOfExpiry();
                    String IssuingCountry = "\r\nIssuingCountry: "+mrzClass.getIssuingState();
                    String Citizenship = "\r\nCitizenship: "+mrzClass.getNationality();
                    String DocumentNumber = "\r\nDocumentNumber: "+mrzClass.getDocumentNumber();
                    String DocType = "\r\nDocumentType: "+mrzClass.getDocumentType();

                    StringBuilder sb = new StringBuilder();
                    sb.append(LastName);
                    sb.append(FirstName);
                    sb.append(DOB);
                    sb.append(DocType);
                    sb.append(DocumentNumber);
                    sb.append(Citizenship);
                    sb.append(IssuingCountry);
                    sb.append(ExpirationDate);
                    Files.write(Paths.get("mrz_parsed.txt"),sb.toString().getBytes());

                    System.out.println("OK MRZ taken and parsed");

                }
                if(lstSpis.contains(LDSFile.EF_DG2_TAG))
                {
                    CardFileInputStream dg2stream = passportService.getInputStream(PassportService.EF_DG2);
                    Files.write(Paths.get("dg2.bin"),dg2stream.readAllBytes());
                    InputStream is = new BufferedInputStream(new FileInputStream("dg2.bin"));
                    DG2File dg2Plik = new DG2File(is);
                    is.close();


                    List<FaceInfo> lstTwarz = dg2Plik.getFaceInfos();

                    if(lstTwarz.size()>=1)
                    {
                        FaceInfo fi = lstTwarz.get(0);
                        List<FaceImageInfo> lstFii = fi.getFaceImageInfos();
                        for(FaceImageInfo fii : lstFii)
                        {
                            String mime = fii.getMimeType();
                            if(mime.endsWith("jp2"))
                            {
                                InputStream iis = fii.getImageInputStream();

                                Files.write(Paths.get("twarz.jp2"),iis.readAllBytes());
                                java.io.File jp = new java.io.File("twarz.jp2");
                                BufferedImage imageJP2 = ImageIO.read(jp);

                                BufferedImage imageJPEG = new BufferedImage(imageJP2.getWidth(),
                                        imageJP2.getHeight(), BufferedImage.TYPE_INT_RGB);
                                imageJPEG.createGraphics().drawImage(imageJP2, 0, 0, Color.WHITE, null);

                                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                                ImageIO.write(imageJPEG, "jpg",baos);
                                byte[] bJpg = baos.toByteArray();
                                Files.write(Paths.get("twarz.jpeg"),bJpg);

                            }
                            else
                            {
                                InputStream iis = fii.getImageInputStream();
                                Files.write(Paths.get("twarz.jpeg"),iis.readAllBytes());
                            }

                        }
                    }
                    System.out.println("OK Face image taken");

                }

                if(lstSpis.contains(LDSFile.EF_DG14_TAG))
                {
                    CardFileInputStream dg14stream = passportService.getInputStream(PassportService.EF_DG14);
                    Files.write(Paths.get("dg14.bin"),dg14stream.readAllBytes());
                    InputStream is = new BufferedInputStream(new FileInputStream("dg14.bin"));
                    DG14File dg14Plik = new DG14File(is);
                    is.close();

                    Collection<SecurityInfo> cSI = dg14Plik.getSecurityInfos();
                    List<ChipAuthenticationInfo> lstCAI = dg14Plik.getChipAuthenticationInfos();
                    List<ChipAuthenticationPublicKeyInfo> lstCAPKI = dg14Plik.getChipAuthenticationPublicKeyInfos();

                   if(lstCAI.size()>=1&&lstCAPKI.size()>=1)
                    {
                        ChipAuthenticationInfo CAI = lstCAI.get(0);
                        ChipAuthenticationPublicKeyInfo CAPKI = lstCAPKI.get(0);
                        try
                        {
                            EACCAResult caRes = passportService.doEACCA(CAI.getKeyId(), CAI.getObjectIdentifier(), CAPKI.getSubjectPublicKey().getAlgorithm(), CAPKI.getSubjectPublicKey());
                            //ASSUME THERE IS NO EXCEPTION, it's fine..
                            System.out.println("OK CA status: AUTHENTICATED");
                        }
                        catch(Exception ex)
                        {
                            System.out.println("ERR CA status: FAILED\r\n"+ex.getMessage());
                        }
                    }

                    System.out.println("OK Element for Chip Authentication taken");

                }

                if(lstSpis.contains(LDSFile.EF_SOD_TAG)||lstSpis.contains(117)) //POLISH PASS
                {
                    CardFileInputStream sodstream = passportService.getInputStream(PassportService.EF_SOD);
                    byte[] sodbin = sodstream.readAllBytes();
                    Files.write(Paths.get("sod.bin"),sodbin);
                    InputStream is = new BufferedInputStream(new FileInputStream("sod.bin"));
                    SODFile sodPlik = new SODFile(is);
                    is.close();

                    X509Certificate cert = sodPlik.getDocSigningCertificate();

                    Files.write(Paths.get("DS.crt"),cert.getEncoded());

                    System.out.println("OK Security element taken");

                    Map<Integer,byte[]> hashes = sodPlik.getDataGroupHashes();
                    String sodsignatureAlg = sodPlik.getDigestEncryptionAlgorithm();
                    String hashAlgorithm = sodPlik.getSignerInfoDigestAlgorithm();
                    String digestAlg = sodPlik.getDigestAlgorithm();

                    //sod integrity verification
                    byte[] danePodpisane = sodPlik.getEContent();
                    byte[] sodPodpis = sodPlik.getEncryptedDigest();

                    X500Principal issuerCN = sodPlik.getIssuerX500Principal();

                    boolean sodIntegrity=false;
                    //SOD integrity
                    try {
                        if(sodsignatureAlg.contains("SSA"))
                        {
                            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                            String alg = cert.getSigAlgName();
                            Signature verifier = Signature.getInstance("SHA256WITHRSAANDMGF1","BC");
                            //verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1",
                              //      new MGF1ParameterSpec("SHA-256"), 32, 1));
                            verifier.initVerify(cert.getPublicKey()); // This one checks key usage in the cert
                            verifier.update(danePodpisane);
                            sodIntegrity = verifier.verify(sodPodpis);
                        }
                        else {
                            Signature verifier = Signature.getInstance(sodsignatureAlg);
                            verifier.initVerify(cert.getPublicKey()); // This one checks key usage in the cert
                            verifier.update(danePodpisane);
                            sodIntegrity = verifier.verify(sodPodpis);
                        }
                        if(sodIntegrity==true)
                        {
                            System.out.println("OK SOD integrity check: POSITIVE");
                        }
                        else
                        {
                            System.out.println("OK SOD integrity check: NEGATIVE");
                        }

                    }
                    catch (Exception e) {
                        System.out.println("ERR Couldn't perform SOD integrity check: "+e.getMessage());
                    }

                    //CSCA check
                    try
                    {
                        byte[] binary = Files.readAllBytes(Paths.get("masterlist-content-current.data"));
                        //byte[] binary = Files.readAllBytes(Paths.get("masterlist.ml"));
                        boolean dsTrusted = VerifyCSCA(binary,cert,sodsignatureAlg);
                        if(dsTrusted)
                        {
                            System.out.println("OK DS issuer status: TRUSTED");

                        }
                        else
                        {
                            System.out.println("ERR DS issuer status: No proper, trusted CSCA found");
                        }

                    }
                    catch(Exception ex)
                    {
                        System.out.println("ERR Error parsing masterlist: \r\n"+ex.getMessage());
                    }

                    System.out.println("OK Performing Passive Authentication");
                    try
                    {
                        Map<Integer,Boolean> map = PerformHashCheck(hashes,digestAlg);
                        if(map.get(1)==true)
                        {
                            System.out.println("OK Hash of DG1 status: OK");
                        }
                        else
                        {
                            System.out.println("ERR Hash of DG1 status: FAILED");
                        }
                        if(map.get(2)==true)
                        {
                            System.out.println("OK Hash of DG2 status: OK");
                        }
                        else
                        {
                            System.out.println("ERR Hash of DG2 status: FAILED");
                        }
                        if(map.get(14)!=null&&map.get(14)==true)
                        {
                            System.out.println("OK Hash of DG14 status: OK");
                        }
                        else
                        {
                            if(map.get(14)!=null&&map.get(14)==false) {
                                System.out.println("ERR Hash of DG14 status: FAILED");
                            }
                        }
                    }
                    catch(Exception ex)
                    {
                        System.out.println("ERR Performing passive authentication:\r\n"+ex.getMessage());
                    }
                }

                passportService.close();
                System.out.println("OK Session closed");
            }
            else
            {
                System.out.println("ERR No suitable readers found or document not present");

            }

        }
        catch(Exception ex)
        {
            System.out.print("ERR error during reading document: "+ex.getMessage()+"\r\n"+ex.getStackTrace());

        }

    }

    private static List<PACEInfo> getPACEInfos(Collection<SecurityInfo> securityInfos) {
        List<PACEInfo> paceInfos = new ArrayList<PACEInfo>();

        if (securityInfos == null) {
            return paceInfos;
        }

        for (SecurityInfo securityInfo: securityInfos) {
            if (securityInfo instanceof PACEInfo) {
                paceInfos.add((PACEInfo)securityInfo);
            }
        }

        return paceInfos;
    }

    private static void CleanOutputDirectory() throws Exception
    {
        if(Files.exists(Paths.get("dg1.bin")))
        {
            Files.delete(Paths.get("dg1.bin"));
        }
        if(Files.exists(Paths.get("dg2.bin")))
        {
            Files.delete(Paths.get("dg2.bin"));
        }
        if(Files.exists(Paths.get("dg14.bin")))
        {
            Files.delete(Paths.get("dg14.bin"));
        }
        if(Files.exists(Paths.get("sod.bin")))
        {
            Files.delete(Paths.get("sod.bin"));
        }
        if(Files.exists(Paths.get("twarz.jp2")))
        {
            Files.delete(Paths.get("twarz.jp2"));
        }
        if(Files.exists(Paths.get("twarz.jpeg")))
        {
            Files.delete(Paths.get("twarz.jpeg"));
        }
        if(Files.exists(Paths.get("mrz.txt")))
        {
            Files.delete(Paths.get("mrz.txt"));
        }
        if(Files.exists(Paths.get("mrz_parsed.txt")))
        {
            Files.delete(Paths.get("mrz_parsed.txt"));
        }
    }

    private static Map<Integer,Boolean> PerformHashCheck(Map<Integer,byte[]> mapa,String hashAlgorithm) throws Exception
    {
        Map<Integer,Boolean> mapaOut = new HashMap<>();

        MessageDigest md = MessageDigest.getInstance(hashAlgorithm);

        if(Files.exists(Paths.get("dg1.bin")))
        {
            byte[] hashdg1fromsod = mapa.get(1);
            FileInputStream fis = new FileInputStream("dg1.bin");
            md.reset();
            byte[] dg1fromfile = fis.readAllBytes();
            fis.close();
            byte[] hashdg1created = md.digest(dg1fromfile);

            Boolean dg1compareRes = Arrays.equals(hashdg1created,hashdg1fromsod);

            mapaOut.put(1,dg1compareRes);
        }
        if(Files.exists(Paths.get("dg2.bin")))
        {
            byte[] hashdg2fromsod = mapa.get(2);

            FileInputStream fis = new FileInputStream("dg2.bin");
            md.reset();
            byte[] dg2file = fis.readAllBytes();
            fis.close();
            byte[] hashdg2created = md.digest(dg2file);

            Boolean dg2compareRes = Arrays.equals(hashdg2created,hashdg2fromsod);
            mapaOut.put(2,dg2compareRes);
        }
        if(Files.exists(Paths.get("dg14.bin")))
        {
            FileInputStream fis = new FileInputStream("dg14.bin");
            md.reset();
            byte[] dg14file = fis.readAllBytes();
            fis.close();
            byte[] hashdg14created = md.digest(dg14file);

            byte[] hashdg14fromsod = mapa.get(14);
            Boolean dg14compareRes = Arrays.equals(hashdg14created,hashdg14fromsod);
            mapaOut.put(14,dg14compareRes);
        }


        return mapaOut;
    }

    private static Boolean VerifyCSCA(byte[] masterlist,X509Certificate DScert,String alg) throws Exception
    {
        //you have to take sequence right after oid 2.23.136.1.1.2 tag in masterlist - no java implemntation at the moment
        //jmrtd bouncycastle too narrow version - no cmssigned data namespace
        //copy node "SEQUENCE" in asn.1 editor and paste it to masterlist-content-current.data
        //then file is parsed successfully
        //TO DO - in future, add c#implementation
        ASN1Encodable asn1 = ASN1Primitive.fromByteArray(masterlist);

        org.bouncycastle.asn1.icao.CscaMasterList master = org.bouncycastle.asn1.icao.CscaMasterList.getInstance(asn1);
        Certificate[] certs = master.getCertStructs();
        byte[] authkeyidOfDs = getAuthorityKeyId(DScert);

        Boolean isVerified = false;

        for(Certificate c : certs)
        {
            try {
                ASN1Primitive asn = c.getTBSCertificate().getExtensions().getExtension(new ASN1ObjectIdentifier("2.5.29.14")).getParsedValue().toASN1Primitive();
                if (asn instanceof DEROctetString)
                {
                    DEROctetString derOctetString = (DEROctetString) asn;
                    byte[] subKeyId = derOctetString.getOctets();

                    Boolean crossCheckAuthSubj = Arrays.equals(authkeyidOfDs,subKeyId);
                    if(crossCheckAuthSubj==true)
                    {
                        int i = 0;
                        //perform check
                        byte[] encodedCert = c.getEncoded();
                        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                        X509Certificate cert = (X509Certificate)certFactory.generateCertificate(new ByteArrayInputStream(encodedCert));
                        DScert.verify(cert.getPublicKey()); //throws exception if not match
                        isVerified = true;
                        System.out.println("OK Trusted CSCA found and DS verified properly against following CSCA: "+cert.getSubjectDN());
                        break;
                    }
                    else
                    {
                        continue;
                    }
                }


            }
            catch(SignatureException sx)
            {
                isVerified = false;
                System.out.println("ERR Failure during signature verification\r\n certificate used: "+c.getTBSCertificate().getSubject()+"\r\n"+sx.getMessage());
                break;
            }
            catch(Exception ex)
            {
                System.out.println("ERR Error veryfing DS issuer: "+ex.getMessage()+"\r\nCertificate made exception:"+c.getTBSCertificate().getIssuer());
                isVerified = false;
                continue;
            }
        }

        return isVerified;
    }

    private static byte[] getAuthorityKeyId(X509Certificate cert) throws IOException {

        byte[] extensionValue = cert.getExtensionValue("2.5.29.35");
        if (extensionValue != null) {
            byte[] octets = ASN1OctetString.getInstance(extensionValue).getOctets();
            AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(octets);
            return authorityKeyIdentifier.getKeyIdentifier();
        }
        return null;
    }

    private static ASN1Primitive toDERObject(byte[] data) throws IOException
    {
        ByteArrayInputStream inStream = new ByteArrayInputStream(data);
        ASN1InputStream asnInputStream = new ASN1InputStream(inStream);

        return asnInputStream.readObject();
    }

    private static String ReadConfig(String key)
    {


        try {
            String dir = System.getProperty("user.dir");
            File configFile = null;
            if(Files.exists(Paths.get("config.properties")))
            {
                configFile = new File("config.properties");
            }
            else
            {
                configFile = new File(dir+"\\out\\production\\mrtd\\kansasdev\\config.properties");
            }
            FileReader reader = new FileReader(configFile);
            Properties props = new Properties();
            props.load(reader);

            reader.close();

            return props.get(key).toString();
        } catch (FileNotFoundException ex) {
            System.out.println("ERR no config.properties file\r\n"+ex.getMessage());
            return "";
        } catch (IOException ex) {
            System.out.println("ERR error reading config.properties file");
            return "";
        }
        catch(Exception ex)
        {
            System.out.println("ERR probably no config.properties file!!");
            return "";
        }
    }
}

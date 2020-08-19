module SSLRenew.CSR

open OpenSSL.Core
open OpenSSL.Crypto
open OpenSSL.X509

let generateRsaKeyPair () =
    use rsa = new RSA()
    rsa.GenerateKeys(2048, new BigNumber(0x10021u), null, null)
    rsa.PrivateKeyAsPEM, new CryptoKey(rsa)


let generateCsr (key: CryptoKey) country state locality organization organizationUnit commonName =
    use subject = new X509Name()
    subject.Country <- country
    subject.StateOrProvince <- state
    subject.Locality <- locality
    subject.Organization <- organization
    subject.OrganizationUnit <- organizationUnit
    subject.Common <- commonName
    use req = new X509Request(0, subject, key)
    req.Sign(key, MessageDigest.SHA256)
    req.PEM
